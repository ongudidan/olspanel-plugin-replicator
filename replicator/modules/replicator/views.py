import os
import re
import time
import json
import subprocess
import threading
from datetime import datetime
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, StreamingHttpResponse, HttpResponse
from django.db import connection
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from users.models import Domain
from users.decorators import loginadminoruser

User = get_user_model()

# Directory to write log files
LOG_DIR = "/var/log/olspanel-migration"
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        pass

def get_local_mysql_password():
    """Reads the local MySQL root password from OLSPanel configuration file"""
    pass_file = "/usr/local/olspanel/mypanel/etc/mysqlPassword"
    if os.path.exists(pass_file):
        try:
            with open(pass_file, "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return None

def get_authenticated_user(request):
    """Retrieves authenticated admin, respecting impersonation"""
    if hasattr(request, 'admin_user') and request.admin_user:
        if request.user and request.user.is_authenticated and request.user != request.admin_user:
            return request.user
        return request.admin_user
    return request.user if request.user.is_authenticated else None

def is_admin(user):
    """Helper to check if user is superuser or admin staff"""
    return user and (user.is_superuser or user.is_staff)

def write_key_file(ssh_key_content, job_id):
    """Writes private key content to a secure temporary file and returns its path"""
    key_path = f"/tmp/replicator_key_{job_id}"
    with open(key_path, "w") as f:
        f.write(ssh_key_content.strip() + "\n")
    os.chmod(key_path, 0o600)
    # Ensure correct ownership
    try:
        subprocess.run(["chown", "www-data:www-data", key_path])
    except Exception:
        pass
    return key_path

def clean_key_file(key_path):
    """Safely cleans up temporary SSH private keys"""
    if key_path and os.path.exists(key_path):
        try:
            os.remove(key_path)
        except Exception:
            pass

def build_ssh_args(ip, port, username, password=None, key_path=None):
    """Builds standard SSH options for secure, non-interactive execution"""
    base_args = [
        "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=6",
        "-o", "BatchMode=yes" if key_path else "BatchMode=no"
    ]
    if key_path:
        base_args += ["-i", key_path]
    return base_args

@loginadminoruser
def gui_view(request):
    """Main wizard page view"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return HttpResponse("Unauthorized Access", status=403)

    # Fetch previous jobs from db
    jobs = []
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, source_ip, status, created_at, completed_at FROM replicator_jobs ORDER BY id DESC LIMIT 10")
            columns = [col[0] for col in cursor.description]
            jobs = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception:
        pass

    running_job_id = None
    for j in jobs:
        if j['status'] == 'running':
            running_job_id = j['id']
            break

    base_template = 'whm/base.html' if user.is_superuser else 'users/base.html'
    return render(request, 'replicator/gui.html', {
        'base_template': base_template,
        'user': user,
        'jobs': jobs,
        'running_job_id': running_job_id
    })

@loginadminoruser
def test_ssh_view(request):
    """Validates remote SSH connection parameters"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return JsonResponse({"status": "error", "message": "Unauthorized"}, status=403)

    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)

    ip = request.POST.get('ip', '').strip()
    port = request.POST.get('port', '22').strip()
    username = request.POST.get('username', 'root').strip()
    auth_method = request.POST.get('auth_method', 'key').strip()
    password = request.POST.get('password', '').strip()
    ssh_key = request.POST.get('ssh_key', '').strip()

    if not ip or not port:
        return JsonResponse({"status": "error", "message": "IP Address and Port are required"}, status=400)

    job_id = int(time.time())
    key_path = None
    if auth_method == 'key':
        if not ssh_key:
            return JsonResponse({"status": "error", "message": "SSH Private Key is required for key auth"}, status=400)
        key_path = write_key_file(ssh_key, job_id)

    try:
        ssh_args = build_ssh_args(ip, port, username, password if auth_method == 'password' else None, key_path)
        # Use SSH command to test connection
        cmd = ["ssh"] + ssh_args + [f"{username}@{ip}", "echo 'OK'"]
        
        # If using password auth, we use sshpass if available
        env = os.environ.copy()
        if auth_method == 'password':
            if not subprocess.run(["which", "sshpass"], capture_output=True).returncode == 0:
                return JsonResponse({"status": "error", "message": "sshpass utility is missing on destination server. Please install it or use Key authentication."}, status=400)
            cmd = ["sshpass", "-e"] + cmd
            env["SSHPASS"] = password

        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=12)
        if res.returncode == 0 and 'OK' in res.stdout:
            return JsonResponse({"status": "success", "message": "SSH Connection tested successfully!"})
        else:
            err_msg = res.stderr or res.stdout or "Connection timed out."
            return JsonResponse({"status": "error", "message": f"Connection failed: {err_msg}"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Execution error: {str(e)}"})
    finally:
        clean_key_file(key_path)

@loginadminoruser
def fetch_inventory_view(request):
    """Connects to source server and runs inline python to retrieve domains, databases, and users"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return JsonResponse({"status": "error", "message": "Unauthorized"}, status=403)

    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)

    ip = request.POST.get('ip', '').strip()
    port = request.POST.get('port', '22').strip()
    username = request.POST.get('username', 'root').strip()
    auth_method = request.POST.get('auth_method', 'key').strip()
    password = request.POST.get('password', '').strip()
    ssh_key = request.POST.get('ssh_key', '').strip()

    job_id = int(time.time())
    key_path = None
    if auth_method == 'key':
        key_path = write_key_file(ssh_key, job_id)

    # Inline python script to execute remotely via SSH
    remote_python_script = """
import json
import sys
import os

# Detect OLSPanel base directory dynamically on the remote server
base_dir = '/usr/local/olspanel/mypanel'
base_dir_file = "/etc/olspanel/base_dir"
if os.path.exists(base_dir_file):
    try:
        with open(base_dir_file, "r") as f:
            detected_dir = f.read().strip()
            if detected_dir and os.path.exists(detected_dir):
                base_dir = detected_dir
    except Exception:
        pass

if base_dir not in sys.path:
    sys.path.append(base_dir)
# Append common fallbacks to ensure compatibility across panel versions
for fallback in ['/usr/local/lsws/Example/html/mypanel', '/usr/local/olspanel/mypanel']:
    if os.path.exists(fallback) and fallback not in sys.path:
        sys.path.append(fallback)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mypanel.settings')

inventory = {
    'domains': [],
    'databases': [],
    'users': []
}

# Helper to calculate remote directory size safely
import subprocess
def get_dir_size(path):
    try:
        res = subprocess.run(["du", "-s", "-B1", path], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            return int(res.stdout.split()[0])
    except Exception:
        pass
    return 0

# 1. Fetch MySQL databases directly using system call (runs as root under sudo)
mysql_pass = None
pass_files = [
    os.path.join(base_dir, "etc/mysqlPassword"),
    "/usr/local/olspanel/mypanel/etc/mysqlPassword",
    "/usr/local/lsws/Example/html/mypanel/etc/mysqlPassword",
    "/etc/olspanel/mysqlPassword"
]
for pf in pass_files:
    if os.path.exists(pf):
        try:
            with open(pf, "r") as f:
                mysql_pass = f.read().strip()
                if mysql_pass:
                    break
        except Exception:
            pass

# Query database sizes directly from MySQL stats
db_sizes = {}
try:
    mysql_size_cmd = ["mysql", "-u", "root"]
    if mysql_pass:
        mysql_size_cmd += [f"-p{mysql_pass}"]
    mysql_size_cmd += ["-B", "-N", "-e", "SELECT table_schema, SUM(data_length + index_length) FROM information_schema.TABLES GROUP BY table_schema;"]
    size_res = subprocess.run(mysql_size_cmd, capture_output=True, text=True, timeout=4)
    if size_res.returncode == 0:
        for line in size_res.stdout.strip().split('\\n'):
            parts = line.strip().split('\t')
            if len(parts) == 2:
                try:
                    db_sizes[parts[0]] = int(parts[1])
                except ValueError:
                    pass
except Exception:
    pass

try:
    mysql_cmd = ["mysql", "-u", "root"]
    if mysql_pass:
        mysql_cmd += [f"-p{mysql_pass}"]
    mysql_cmd += ["-B", "-N", "-e", "SHOW DATABASES"]
    
    res = subprocess.run(mysql_cmd, capture_output=True, text=True)
    if res.returncode == 0:
        for line in res.stdout.strip().split('\\n'):
            db_name = line.strip()
            if db_name and db_name not in ['information_schema', 'mysql', 'performance_schema', 'sys']:
                inventory['databases'].append({
                    'name': db_name,
                    'size': db_sizes.get(db_name, 0)
                })
    else:
        inventory['db_error'] = res.stderr
except Exception as e:
    inventory['db_error'] = str(e)

try:
    import django
    django.setup()
    from users.models import Domain
    from django.contrib.auth import get_user_model

    User = get_user_model()

    # Get users mapped to panel
    for u in User.objects.all():
        user_dir = f"/home/{u.username}"
        size = get_dir_size(user_dir) if os.path.exists(user_dir) else 0
        inventory['users'].append({
            'username': u.username,
            'email': u.email,
            'password_hash': u.password,
            'is_superuser': u.is_superuser,
            'size': size
        })

    # Get domains
    for d in Domain.objects.select_related('userid').all():
        owner = d.userid.username if d.userid else 'nobody'
        
        # Self-healing: if owner is nobody or root, parse it from /home/ path or disk owner
        if owner in ['nobody', 'root']:
            if d.path and d.path.startswith('/home/'):
                parts = d.path.split('/')
                if len(parts) > 2:
                    owner = parts[2]
            
            # If still unresolved, look up disk owner of the folder
            if owner in ['nobody', 'root'] and d.path and os.path.exists(d.path):
                try:
                    import pwd
                    stat_info = os.stat(d.path)
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                except Exception:
                    pass

        size = get_dir_size(d.path) if d.path and os.path.exists(d.path) else 0
        inventory['domains'].append({
            'domain': d.domain,
            'username': owner,
            'path': d.path,
            'size': size
        })

    print(json.dumps({'status': 'success', 'inventory': inventory}))
except Exception as e:
    # Fallback to system query if Django loading fails
    try:
        import pwd
        users = [p.pw_name for p in pwd.getpwall() if p.pw_uid >= 1000 and p.pw_dir.startswith('/home')]
        inventory['users'] = [{
            'username': u, 
            'email': '', 
            'password_hash': '', 
            'is_superuser': False,
            'size': get_dir_size(f'/home/{u}')
        } for u in users]
        
        # List virtual host folders
        vh_dir = "/usr/local/lsws/conf/vhosts"
        if os.path.exists(vh_dir):
            for d in os.listdir(vh_dir):
                if os.path.isdir(os.path.join(vh_dir, d)) and d not in ['Example']:
                    # Self-healing fallback: inspect the config folder owner on disk
                    owner = 'nobody'
                    try:
                        stat_info = os.stat(os.path.join(vh_dir, d))
                        owner = pwd.getpwuid(stat_info.st_uid).pw_name
                    except Exception:
                        pass
                    
                    if owner in ['nobody', 'root']:
                        # Check /home to see if there is a corresponding user directory
                        for u in users:
                            if os.path.exists(f"/home/{u}/{d}"):
                                owner = u
                                break
                    
                    doc_root = f'/home/{owner}/{d}'
                    inventory['domains'].append({
                        'domain': d, 
                        'username': owner, 
                        'path': doc_root,
                        'size': get_dir_size(doc_root)
                    })
        
        print(json.dumps({'status': 'success', 'inventory': inventory, 'fallback': True, 'error': str(e)}))
    except Exception as fallback_err:
        print(json.dumps({'status': 'error', 'message': f"Core fail: {str(e)} | Fallback fail: {str(fallback_err)}"}))
"""

    try:
        ssh_args = build_ssh_args(ip, port, username, password if auth_method == 'password' else None, key_path)
        # Execute python within the OLSPanel virtual environment if available, otherwise fallback to system python3
        if username != 'root':
            py_selector = "if [ -f /root/venv/bin/python ]; then sudo /root/venv/bin/python; else sudo python3; fi"
        else:
            py_selector = "if [ -f /root/venv/bin/python ]; then /root/venv/bin/python; else python3; fi"
        cmd = ["ssh"] + ssh_args + [f"{username}@{ip}", py_selector]
        
        env = os.environ.copy()
        if auth_method == 'password':
            cmd = ["sshpass", "-e"] + cmd
            env["SSHPASS"] = password

        # Run connection piping the script text to stdin
        res = subprocess.run(cmd, env=env, input=remote_python_script, capture_output=True, text=True, timeout=20)
        
        if res.returncode == 0:
            # Parse response
            try:
                data = json.loads(res.stdout.strip())
                if data.get('status') == 'success':
                    return JsonResponse({"status": "success", "inventory": data.get('inventory')})
                else:
                    return JsonResponse({"status": "error", "message": data.get('message', 'Remote script returned error')})
            except Exception:
                return JsonResponse({"status": "error", "message": f"Failed to parse remote script output. Raw stdout:\n{res.stdout}\nStderr:\n{res.stderr}"})
        else:
            return JsonResponse({"status": "error", "message": f"Failed running remote discovery: {res.stderr or res.stdout}"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": f"Server execution exception: {str(e)}"})
    finally:
        clean_key_file(key_path)

@loginadminoruser
def start_migration_view(request):
    """Inserts a migration job record and starts a background thread to handle data sync"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return JsonResponse({"status": "error", "message": "Unauthorized"}, status=403)

    if request.method != 'POST':
        return JsonResponse({"status": "error", "message": "POST required"}, status=400)

    # Decode selection parameters
    ip = request.POST.get('ip', '').strip()
    port = request.POST.get('port', '22').strip()
    username = request.POST.get('username', 'root').strip()
    auth_method = request.POST.get('auth_method', 'key').strip()
    password = request.POST.get('password', '').strip()
    ssh_key = request.POST.get('ssh_key', '').strip()

    selected_users_str = request.POST.get('selected_users', '[]')
    selected_domains_str = request.POST.get('selected_domains', '[]')
    selected_databases_str = request.POST.get('selected_databases', '[]')

    try:
        selected_users = json.loads(selected_users_str)
        selected_domains = json.loads(selected_domains_str)
        selected_databases = json.loads(selected_databases_str)
    except Exception:
        return JsonResponse({"status": "error", "message": "Invalid items selected format"}, status=400)

    # Check if a migration job is already running to prevent disk I/O / CPU thrashing at scale
    with connection.cursor() as cursor:
        cursor.execute("SELECT id FROM replicator_jobs WHERE status = 'running'")
        if cursor.fetchone():
            return JsonResponse({"status": "error", "message": "Another migration job is currently running. Please wait for it to complete."}, status=400)

    # Insert Job into database
    created_at = datetime.now()
    with connection.cursor() as cursor:
        cursor.execute("""
            INSERT INTO replicator_jobs (source_ip, status, log_file, created_at)
            VALUES (%s, 'running', '', %s)
        """, [ip, created_at])
        job_id = cursor.lastrowid

    log_file = os.path.join(LOG_DIR, f"migration_{job_id}.log")
    with connection.cursor() as cursor:
        cursor.execute("UPDATE replicator_jobs SET log_file = %s WHERE id = %s", [log_file, job_id])

    compress_transfer = request.POST.get('compress_transfer') == 'true'

    # Run actual replication asynchronously
    t = threading.Thread(
        target=run_replication_task,
        args=(job_id, ip, port, username, auth_method, password, ssh_key, selected_users, selected_domains, selected_databases, compress_transfer, log_file)
    )
    t.daemon = True
    t.start()

    return JsonResponse({"status": "success", "job_id": job_id})

@loginadminoruser
def stream_logs_view(request, job_id):
    """Streams migration logs in real-time to the wizard progress page"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return HttpResponse("Unauthorized", status=403)

    log_file = os.path.join(LOG_DIR, f"migration_{job_id}.log")

    def log_stream():
        # Wait up to 10 seconds for log file creation
        for _ in range(20):
            if os.path.exists(log_file):
                break
            time.sleep(0.5)

        if not os.path.exists(log_file):
            yield "⏳ Waiting for migration log stream to initialize...\n"
            return

        with open(log_file, "r") as f:
            # First read whatever exists
            content = f.read()
            if content:
                yield content

            # Then stream additions
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    # Check if job is finished
                    is_done = False
                    try:
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT status FROM replicator_jobs WHERE id = %s", [job_id])
                            row = cursor.fetchone()
                            if row and row[0] in ['completed', 'failed']:
                                is_done = True
                    except Exception:
                        pass
                    
                    if is_done:
                        # Print remaining logs
                        remaining = f.read()
                        if remaining:
                            yield remaining
                        yield "\n\n🏁 [Replication Log Stream Terminated]\n"
                        break
                    time.sleep(0.5)

    return StreamingHttpResponse(log_stream(), content_type='text/plain')

@loginadminoruser
def job_status_view(request, job_id):
    """Retrieves status details for a migration job"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return JsonResponse({"status": "error", "message": "Unauthorized"}, status=403)

    with connection.cursor() as cursor:
        cursor.execute("SELECT status, created_at, completed_at FROM replicator_jobs WHERE id = %s", [job_id])
        row = cursor.fetchone()

    if not row:
        return JsonResponse({"status": "error", "message": "Job not found"}, status=404)

    return JsonResponse({
        "status": "success",
        "job_status": row[0],
        "created_at": row[1],
        "completed_at": row[2]
    })

@loginadminoruser
def cancel_migration_view(request, job_id):
    """Flags a running migration job as cancelled"""
    user = get_authenticated_user(request)
    if not is_admin(user):
        return JsonResponse({"status": "error", "message": "Unauthorized Access"}, status=403)

    with connection.cursor() as cursor:
        cursor.execute("SELECT status FROM replicator_jobs WHERE id = %s", [job_id])
        row = cursor.fetchone()
        if not row:
            return JsonResponse({"status": "error", "message": "Job not found"}, status=404)
        if row[0] != 'running':
            return JsonResponse({"status": "error", "message": "Only running jobs can be cancelled"}, status=400)

        cursor.execute("UPDATE replicator_jobs SET status = 'cancelled', completed_at = %s WHERE id = %s", [datetime.now(), job_id])

    return JsonResponse({"status": "success", "message": "Cancellation request submitted."})


# ==========================================
# Core Migration Helper & Task Runner
# ==========================================

def is_job_cancelled(job_id):
    """Checks if the job has been flagged as cancelled in the database"""
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT status FROM replicator_jobs WHERE id = %s", [job_id])
            row = cursor.fetchone()
            return row and row[0] == 'cancelled'
    except Exception:
        return False

def run_replication_task(job_id, ip, port, ssh_username, auth_method, password, ssh_key, users, domains, databases, compress_transfer, log_file):
    """Runs rsync, database dumps, user creations, OLS configurations, and django metadata imports"""
    log_fp = None
    key_path = None
    try:
        log_fp = open(log_file, "w", encoding="utf-8", buffering=1)
        
        def check_cancellation(phase=""):
            if is_job_cancelled(job_id):
                log_fp.write(f"\n❌ Migration cancelled by user during {phase}.\n")
                if key_path and os.path.exists(key_path):
                    try:
                        os.remove(key_path)
                    except Exception:
                        pass
                return True
            return False
        log_fp.write(f"🚀 Starting Server Replication Job #{job_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_fp.write(f"🌍 Source Server: {ip}:{port}\n")
        log_fp.write(f"📦 Items Selected: {len(users)} users, {len(domains)} domains, {len(databases)} databases\n\n")

        # 1. Setup Key File
        if auth_method == 'key':
            log_fp.write("🔑 Writing secure temporary private key file...\n")
            key_path = write_key_file(ssh_key, job_id)
        
        ssh_args = build_ssh_args(ip, port, ssh_username, password if auth_method == 'password' else None, key_path)

        env = os.environ.copy()
        if auth_method == 'password':
            env["SSHPASS"] = password

        def run_ssh_command(cmd_str):
            """Executes a command on the source server via SSH"""
            cmd = ["ssh"] + ssh_args + [f"{ssh_username}@{ip}", cmd_str]
            if auth_method == 'password':
                cmd = ["sshpass", "-e"] + cmd
            return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)

        # 2. Replicate Linux System Users
        log_fp.write("==================================================\n")
        log_fp.write("👥 Phase 1: Replicating Linux System Users\n")
        log_fp.write("==================================================\n")
        
        for u in users:
            if check_cancellation("Phase 1 (User replication)"): return
            username = u.get('username')
            password_hash = u.get('password_hash', '')
            is_superuser = u.get('is_superuser', False)
            email = u.get('email', '')

            log_fp.write(f"👤 Processing user '{username}'...\n")

            # Get user shell and home path from source passwd
            pwd_res = run_ssh_command(f"getent passwd {username}")
            if pwd_res.returncode != 0:
                log_fp.write(f"⚠️ User '{username}' passwd not found on source server. Skipping Linux account setup.\n")
                continue

            # Format: username:x:uid:gid:gecos:home:shell
            pwd_parts = pwd_res.stdout.strip().split(':')
            if len(pwd_parts) < 7:
                log_fp.write(f"⚠️ Failed to parse passwd info for user '{username}'. Skipping Linux account setup.\n")
                continue

            uid = pwd_parts[2]
            gid = pwd_parts[3]
            home_dir = pwd_parts[5]
            shell = pwd_parts[6]

            # Get password hash from remote /etc/shadow
            shadow_res = run_ssh_command(f"sudo getent shadow {username}")
            remote_shadow_hash = None
            if shadow_res.returncode == 0:
                shadow_parts = shadow_res.stdout.strip().split(':')
                if len(shadow_parts) >= 2 and shadow_parts[1] not in ['*', '!', 'x', '']:
                    remote_shadow_hash = shadow_parts[1]

            # Check if user already exists locally
            local_user_check = subprocess.run(["getent", "passwd", username], capture_output=True)
            if local_user_check.returncode == 0:
                log_fp.write(f"ℹ️ System user '{username}' already exists locally. Updating home directory and shell...\n")
                subprocess.run(["usermod", "-s", shell, "-d", home_dir, username])
            else:
                # Create user
                create_cmd = ["useradd", "-m", "-s", shell, "-d", home_dir]
                if remote_shadow_hash:
                    # Create with encrypted password hash
                    create_cmd += ["-p", remote_shadow_hash]
                create_cmd.append(username)

                log_fp.write(f"➕ Creating system user '{username}' locally...\n")
                res = subprocess.run(create_cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    log_fp.write(f"❌ Failed to create system user '{username}': {res.stderr}\n")
                else:
                    log_fp.write(f"🟢 Successfully created system user '{username}'.\n")

            # Sync user Django metadata
            try:
                django_user, created = User.objects.get_or_create(
                    username=username,
                    defaults={
                        'email': email,
                        'password': password_hash or '!',
                        'is_active': True,
                        'is_staff': is_superuser,
                        'is_superuser': is_superuser
                    }
                )
                if not created:
                    # Sync password hash if changed
                    if password_hash and django_user.password != password_hash:
                        django_user.password = password_hash
                        django_user.save()
                log_fp.write(f"🔒 Django database user record synced for '{username}'.\n")
            except Exception as e:
                log_fp.write(f"⚠️ Warning syncing Django user record: {str(e)}\n")

        # 3. Synchronize Web Directories (Rsync)
        log_fp.write("\n==================================================\n")
        log_fp.write("📁 Phase 2: Transferring Web Content & Files\n")
        log_fp.write("==================================================\n")

        for d in domains:
            if check_cancellation("Phase 2 (File transfer)"): return
            domain_name = d.get('domain')
            owner = d.get('username')
            source_path = d.get('path', f'/home/{owner}/{domain_name}')

            log_fp.write(f"📂 Syncing website files for '{domain_name}'...\n")
            
            # Resolve destination path
            dest_path = f"/home/{owner}/{domain_name}"
            # Ensure parent directories exist
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)

            # Build rsync command
            # Using absolute path key if key auth is active
            ssh_rsync_opts = f"ssh -p {port} -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=6"
            if key_path:
                ssh_rsync_opts += f" -i {key_path}"

            # Apply compression flag dynamically based on user config (CPU vs Network compression tuning)
            rsync_flags = "-az" if compress_transfer else "-a"
            rsync_cmd = ["rsync", rsync_flags, "--timeout=60", "--delete"]
            # Use sudo on the remote source if connecting as a non-root admin (like ubuntu)
            if ssh_username != 'root':
                rsync_cmd += ["--rsync-path=sudo rsync"]
            rsync_cmd += ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:{source_path}/", f"{dest_path}/"]
            
            log_fp.write(f"⚡ Running rsync file transfer (silent mode, compression={'ON' if compress_transfer else 'OFF'})...\n")
            log_fp.write("Syncing files ")
            
            # Run rsync
            rsync_proc = subprocess.Popen(rsync_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Print a status tick and check cancellation every 5 seconds
            last_tick = time.time()
            while rsync_proc.poll() is None:
                if time.time() - last_tick >= 5:
                    if is_job_cancelled(job_id):
                        log_fp.write("\n❌ Migration cancelled. Terminating active rsync process...\n")
                        rsync_proc.terminate()
                        rsync_proc.wait()
                        if key_path and os.path.exists(key_path):
                            try:
                                os.remove(key_path)
                            except Exception:
                                pass
                        return
                    log_fp.write(".")
                    last_tick = time.time()
                time.sleep(0.5)
            log_fp.write("\n")
            
            rsync_proc.wait()
            if rsync_proc.returncode == 0:
                log_fp.write(f"🟢 File transfer complete. Adjusting file permissions for {owner}...\n")
                subprocess.run(["chown", "-R", f"{owner}:{owner}", dest_path])
            else:
                log_fp.write(f"❌ File transfer failed with code {rsync_proc.returncode}.\n")

            # Replicate Let's Encrypt SSL folder if present
            log_fp.write(f"🔒 Checking SSL certificates for '{domain_name}'...\n")
            # Use sudo to check /etc/letsencrypt permission-restricted folder on remote
            ssl_check_cmd = f"sudo [ -d /etc/letsencrypt/live/{domain_name} ] && echo 'SSL_EXISTS'"
            ssl_res = run_ssh_command(ssl_check_cmd)
            if 'SSL_EXISTS' in ssl_res.stdout:
                log_fp.write(f"🔑 Copying Let's Encrypt SSL folders for '{domain_name}'...\n")
                # Create local SSL directories
                os.makedirs(f"/etc/letsencrypt/live/{domain_name}", exist_ok=True)
                os.makedirs(f"/etc/letsencrypt/archive/{domain_name}", exist_ok=True)
                os.makedirs(f"/etc/letsencrypt/renewal", exist_ok=True)

                # Sync live, archive, and renewal config
                rsync_ssl_args = ["rsync", "-avz"]
                if ssh_username != 'root':
                    rsync_ssl_args += ["--rsync-path=sudo rsync"]

                subprocess.run(rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/live/{domain_name}/", f"/etc/letsencrypt/live/{domain_name}/"])
                subprocess.run(rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/archive/{domain_name}/", f"/etc/letsencrypt/archive/{domain_name}/"])
                subprocess.run(rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/renewal/{domain_name}.conf", f"/etc/letsencrypt/renewal/{domain_name}.conf"])
                
                # Fix symlinks inside letsencrypt/live/ which might be broken by rsync
                # Usually they point relatively to ../../archive/domain/file.pem
                live_dir = f"/etc/letsencrypt/live/{domain_name}"
                for file_name in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                    link_path = os.path.join(live_dir, file_name)
                    if os.path.islink(link_path):
                        # Symlink exists, verify target
                        pass
                    else:
                        # Re-create correct symlink relative mapping
                        archive_target = f"../../archive/{domain_name}/{file_name}"
                        if os.path.exists(link_path):
                            os.remove(link_path)
                        os.symlink(archive_target, link_path)
                
                log_fp.write(f"🟢 SSL Certificate files successfully synced.\n")

        # 4. Synchronize Databases & Users (MySQL)
        log_fp.write("\n==================================================\n")
        log_fp.write("🗄️ Phase 3: Copying & Restoring Databases\n")
        log_fp.write("==================================================\n")

        # 4a. Replicate MySQL database users and grants
        log_fp.write("👥 Fetching database users and grants from source...\n")
        
        # Fetch remote MySQL base directory dynamically
        remote_base_dir = "/usr/local/olspanel/mypanel"
        dir_res = run_ssh_command("sudo cat /etc/olspanel/base_dir")
        if dir_res.returncode == 0 and dir_res.stdout.strip():
            remote_base_dir = dir_res.stdout.strip()
            
        # Fetch remote MySQL password from the remote server's configuration file (checking multiple version paths)
        remote_mysql_pass = ""
        for remote_pf in [
            f"{remote_base_dir}/etc/mysqlPassword",
            "/usr/local/olspanel/mypanel/etc/mysqlPassword",
            "/usr/local/lsws/Example/html/mypanel/etc/mysqlPassword"
        ]:
            mysql_pass_res = run_ssh_command(f"sudo cat {remote_pf}")
            if mysql_pass_res.returncode == 0 and mysql_pass_res.stdout.strip():
                remote_mysql_pass = mysql_pass_res.stdout.strip()
                break
            
        mysql_remote_auth = "mysql -u root"
        if remote_mysql_pass:
            mysql_remote_auth += f" -p'{remote_mysql_pass}'"
        
        # Script to output Grants statement with passwords (use sudo to access socket/password-linked mysql)
        grants_dump_cmd = f"sudo {mysql_remote_auth} -B -N -e \"SELECT DISTINCT CONCAT('SHOW GRANTS FOR \\'', User, '\\'@\\'', Host, '\\';') FROM mysql.user WHERE User NOT IN ('root', 'mysql.sys', 'mysql.infoschema', 'mysql.session', 'mariadb.sys', 'debian-sys-maint');\""
        grants_list_res = run_ssh_command(grants_dump_cmd)
        
        if grants_list_res.returncode == 0:
            grants_sql = ""
            for show_grant_cmd in grants_list_res.stdout.strip().split('\n'):
                if show_grant_cmd.strip():
                    # Run SQL command via remote mysql using sudo
                    grant_val_res = run_ssh_command(f"sudo {mysql_remote_auth} -B -N -e \"{show_grant_cmd}\"")
                    if grant_val_res.returncode == 0:
                        for grant_line in grant_val_res.stdout.strip().split('\n'):
                            if grant_line:
                                # We capture and cleanup remote grants
                                grants_sql += grant_line + ";\n"

            # Execute grants locally on destination database
            if grants_sql:
                log_fp.write("🔑 Restoring database users and grants locally...\n")
                try:
                    # Write temp file and load it
                    sql_temp_path = f"/tmp/grants_{job_id}.sql"
                    with open(sql_temp_path, "w") as sql_f:
                        sql_f.write(grants_sql)
                    
                    local_mysql_pass = get_local_mysql_password()
                    local_mysql_auth = "mysql -u root"
                    if local_mysql_pass:
                        local_mysql_auth += f" -p'{local_mysql_pass}'"
                        
                    restore_grants_res = subprocess.run(f"{local_mysql_auth} < {sql_temp_path}", shell=True, capture_output=True, text=True)
                    if restore_grants_res.returncode == 0:
                        log_fp.write("🟢 Database user credentials synced successfully.\n")
                    else:
                        # Fallback try executing line-by-line ignoring errors
                        log_fp.write("⚠️ Direct SQL grants import warning: trying line-by-line fallback...\n")
                        with connection.cursor() as cursor:
                            for line in grants_sql.split('\n'):
                                if line.strip() and not line.startswith('--'):
                                    try:
                                        cursor.execute(line)
                                    except Exception:
                                        pass
                        log_fp.write("🟢 Database credentials migration fallback executed.\n")
                    os.remove(sql_temp_path)
                except Exception as e:
                    log_fp.write(f"⚠️ Warning migrating database users/grants: {str(e)}\n")
        else:
            log_fp.write("⚠️ Could not read MySQL user list from source. Database connections may require manual setups if database users differ from site users.\n")

        # 4b. Replicate Databases
        local_mysql_pass = get_local_mysql_password()
        for db_name in databases:
            if check_cancellation("Phase 3 (Database replication)"): return
            log_fp.write(f"🗄️ Replicating database '{db_name}'...\n")
            log_fp.write(f"⚠️ WARNING: This will overwrite/drop local tables in '{db_name}'. If the site is already live here, it may experience temporary query errors during the import.\n")
            
            # Create local MySQL db
            create_db_cmd = ["mysql", "-u", "root"]
            if local_mysql_pass:
                create_db_cmd += [f"-p{local_mysql_pass}"]
            create_db_cmd += ["-e", f"CREATE DATABASE IF NOT EXISTS {db_name} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"]
            subprocess.run(create_db_cmd)

            # Dump from source and pipe straight to destination MySQL
            ssh_dump_opts = "ssh"
            if auth_method == 'key':
                ssh_dump_opts += f" -p {port} -i {key_path} -o StrictHostKeyChecking=no"
            else:
                ssh_dump_opts = f"sshpass -e ssh -p {port} -o StrictHostKeyChecking=no"

            mysqldump_bin = "sudo mysqldump" if ssh_username != 'root' else "mysqldump"
            
            remote_mysqldump_cmd = f"{mysqldump_bin} -u root"
            if remote_mysql_pass:
                remote_mysqldump_cmd += f" -p'{remote_mysql_pass}'"
            remote_mysqldump_cmd += f" --single-transaction {db_name}"
            
            local_mysql_cmd = "mysql -u root"
            if local_mysql_pass:
                local_mysql_cmd += f" -p'{local_mysql_pass}'"
            local_mysql_cmd += f" {db_name}"

            dump_restore_cmd = f"{ssh_dump_opts} {ssh_username}@{ip} '{remote_mysqldump_cmd}' | {local_mysql_cmd}"
            
            log_fp.write("⚡ Streaming dump & restore pipeline...\n")
            try:
                # Add 30-minute timeout to prevent infinite socket hangs at scale
                # Pass password securely via env variables in shell environment
                res = subprocess.run(dump_restore_cmd, shell=True, env=env, capture_output=True, text=True, timeout=1800)
                if res.returncode == 0:
                    log_fp.write(f"🟢 Database '{db_name}' successfully imported.\n")
                else:
                    log_fp.write(f"❌ Database '{db_name}' import failed: {res.stderr}\n")
            except subprocess.TimeoutExpired:
                log_fp.write(f"❌ Database '{db_name}' import timed out (exceeded 30 mins).\n")

        # 5. Sync OpenLiteSpeed configs & Django records
        log_fp.write("\n==================================================\n")
        log_fp.write("🌐 Phase 4: Rebuilding OpenLiteSpeed Configs & Panel metadata\n")
        log_fp.write("==================================================\n")

        for d in domains:
            if check_cancellation("Phase 4 (OLS Config sync)"): return
            domain_name = d.get('domain')
            owner = d.get('username')
            doc_root = f"/home/{owner}/{domain_name}"

            log_fp.write(f"🌐 Synchronizing OLS Vhost configurations for '{domain_name}'...\n")
            
            # Sync OLS Vhost config folder
            vhost_src = f"/usr/local/lsws/conf/vhosts/{domain_name}/"
            vhost_dest = f"/usr/local/lsws/conf/vhosts/{domain_name}/"
            
            os.makedirs(vhost_dest, exist_ok=True)
            ssh_rsync_opts = f"ssh -p {port} -o StrictHostKeyChecking=no"
            if key_path:
                ssh_rsync_opts += f" -i {key_path}"

            subprocess.run(["rsync", "-avz", "-e", ssh_rsync_opts, f"{ssh_username}@{ip}:{vhost_src}", vhost_dest])
            subprocess.run(["chown", "-R", "lsadm:lsadm", vhost_dest])

            # Apply virtual host mapping inside destination's httpd_config.conf
            try:
                registered = register_domain_in_httpd_config(domain_name, doc_root)
                if registered:
                    log_fp.write(f"🟢 Mapped '{domain_name}' to OpenLiteSpeed httpd_config.conf.\n")
                else:
                    log_fp.write(f"ℹ️ '{domain_name}' already declared in httpd_config.conf.\n")
            except Exception as e:
                log_fp.write(f"❌ Failed mapping '{domain_name}' to OpenLiteSpeed config: {str(e)}\n")

            # Create Domain Metadata in OLSPanel Database
            try:
                user_obj = User.objects.filter(username=owner).first()
                domain_obj, created = Domain.objects.get_or_create(
                    domain=domain_name,
                    defaults={
                        'userid': user_obj,
                        'path': doc_root
                    }
                )
                if created:
                    log_fp.write(f"🟢 Registered '{domain_name}' metadata in OLSPanel dashboard records.\n")
                else:
                    log_fp.write(f"ℹ️ '{domain_name}' already exists in panel database.\n")
            except Exception as e:
                log_fp.write(f"⚠️ Warning adding domain metadata to DB: {str(e)}\n")

        # Reload OpenLiteSpeed to apply configurations
        log_fp.write("\n🔄 Reloading OpenLiteSpeed web server...\n")
        subprocess.run(["/usr/local/lsws/bin/lswsctrl", "reload"])
        log_fp.write("🟢 OpenLiteSpeed reloaded.\n")

        # Job Completed Successfully
        completed_at = datetime.now()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE replicator_jobs SET status = 'completed', completed_at = %s WHERE id = %s", [completed_at, job_id])
        
        log_fp.write(f"\n🎉 Server Migration Replication completed successfully at {completed_at.strftime('%Y-%m-%d %H:%M:%S')}!\n")
    
    except Exception as err:
        completed_at = datetime.now()
        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE replicator_jobs SET status = 'failed', completed_at = %s WHERE id = %s", [completed_at, job_id])
        except Exception:
            pass

        if log_fp:
            log_fp.write(f"\n❌ Migration Failed with unexpected error: {str(err)}\n")
            log_fp.write(f"Timestamp: {completed_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
    finally:
        if log_fp:
            log_fp.close()
        clean_key_file(key_path)

def register_domain_in_httpd_config(domain_name, doc_root):
    """Parses and updates /usr/local/lsws/conf/httpd_config.conf to link the vhost configurations"""
    config_path = "/usr/local/lsws/conf/httpd_config.conf"
    if not os.path.exists(config_path):
        raise FileNotFoundError("Master OpenLiteSpeed configuration file not found.")

    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if virtualhost block already exists
    pattern_vh = rf"virtualhost\s+{re.escape(domain_name)}\s*\{{"
    if re.search(pattern_vh, content):
        # Already exists
        return False

    # 1. Append Virtual Host block
    vhost_block = f"""
virtualhost {domain_name} {{
  vhRoot                  {doc_root}
  configFile              conf/vhosts/{domain_name}/vhost.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              2
}}
"""
    content = content.rstrip() + "\n" + vhost_block

    # 2. Append mappings under listener Default and listener SSL
    # Listeners look like:
    # listener Default {
    #   address *:80
    #   secure 0
    #   map domain domain
    # }
    
    def add_map_to_listener(conf_text, listener_name):
        pattern_listener = rf"listener\s+{re.escape(listener_name)}\s*\{{[^}}]*\}}"
        match = re.search(pattern_listener, conf_text)
        if match:
            listener_block = match.group(0)
            map_pattern = rf"map\s+{re.escape(domain_name)}\s+{re.escape(domain_name)}"
            if not re.search(map_pattern, listener_block):
                # We need to insert a map line before the closing bracket
                lines = listener_block.split('\n')
                inserted = False
                for i in range(len(lines) - 1, -1, -1):
                    if '}' in lines[i]:
                        lines.insert(i, f"  map                     {domain_name} {domain_name}")
                        inserted = True
                        break
                if inserted:
                    updated_listener = '\n'.join(lines)
                    conf_text = conf_text.replace(listener_block, updated_listener)
        return conf_text

    content = add_map_to_listener(content, "Default")
    content = add_map_to_listener(content, "SSL")

    with open(config_path, "w", encoding="utf-8") as f:
        f.write(content)

    return True
