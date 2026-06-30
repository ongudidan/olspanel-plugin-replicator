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

# Helper to dynamically resolve true owner and path for domains
def resolve_domain_owner_and_path(domain_name, database_owner, database_path, system_users):
    owner = database_owner
    path = database_path
    
    if owner in ['root', 'nobody', 'lsadm']:
        # 1. Match by username inside the domain name (e.g. deltamarkethub.co.ke -> deltamarkethub)
        matched_user = None
        for u in system_users:
            if u in domain_name:
                matched_user = u
                break
        
        # 2. Check path existence on source disk
        users_to_check = [matched_user] if matched_user else system_users
        found = False
        for u in users_to_check:
            if not u or u in ['root', 'nobody', 'lsadm']:
                continue
            for p in [f"/home/{u}/{domain_name}", f"/home/{u}/public_html", f"/home/{u}/public_htm"]:
                if os.path.exists(p):
                    owner = u
                    path = p
                    found = True
                    break
            if found:
                break
        
        if not found:
            for u in system_users:
                if u in ['root', 'nobody', 'lsadm']:
                    continue
                for p in [f"/home/{u}/{domain_name}", f"/home/{u}/public_html", f"/home/{u}/public_htm"]:
                    if os.path.exists(p):
                        owner = u
                        path = p
                        found = True
                        break
                if found:
                    break

    # If owner is valid, but path points to root config paths or is unset, rewrite to true home path
    if owner not in ['root', 'nobody', 'lsadm']:
        if not path or path.startswith('/home/root') or path.startswith('/home/nobody') or not path.startswith('/home/'):
            path = f"/home/{owner}/{domain_name}"
            if os.path.exists(f"/home/{owner}/public_html"):
                path = f"/home/{owner}/public_html"
            elif os.path.exists(f"/home/{owner}/public_htm"):
                path = f"/home/{owner}/public_htm"
                
    return owner, path

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

    # Gather usernames
    system_users_list = [u.username for u in User.objects.all()]

    # Get domains
    for d in Domain.objects.select_related('userid').all():
        db_owner = d.userid.username if d.userid else 'nobody'
        owner, path = resolve_domain_owner_and_path(d.domain, db_owner, d.path, system_users_list)

        size = get_dir_size(path) if path and os.path.exists(path) else 0
        inventory['domains'].append({
            'domain': d.domain,
            'username': owner,
            'path': path,
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
                    
                    # Resolve path
                    owner, path = resolve_domain_owner_and_path(d, owner, f'/home/{owner}/{d}', users)
                    inventory['domains'].append({
                        'domain': d, 
                        'username': owner, 
                        'path': path,
                        'size': get_dir_size(path)
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

    # Detect and save admin session key (from SeparateAdminSessionMiddleware)
    admin_session_key = None
    if hasattr(request, 'admin_session') and request.admin_session:
        if not request.admin_session.session_key:
            request.admin_session.save()
        admin_session_key = request.admin_session.session_key

    # Detect and save user session key (standard Django SessionMiddleware)
    user_session_key = None
    if hasattr(request, 'session') and request.session:
        if not request.session.session_key:
            request.session.save()
        user_session_key = request.session.session_key

    # Run actual replication asynchronously
    t = threading.Thread(
        target=run_replication_task,
        args=(job_id, ip, port, username, auth_method, password, ssh_key, selected_users, selected_domains, selected_databases, compress_transfer, log_file, admin_session_key, user_session_key)
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
                            if row and row[0] in ['completed', 'failed', 'cancelled']:
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

def run_replication_task(job_id, ip, port, ssh_username, auth_method, password, ssh_key, users, domains, databases, compress_transfer, log_file, admin_session_key=None, user_session_key=None):
    """Runs rsync, database dumps, user creations, OLS configurations, and django metadata imports"""
    log_fp = None
    key_path = None
    try:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        log_fp = open(log_file, "w", encoding="utf-8", buffering=1)
        
        def check_cancellation(phase=""):
            if is_job_cancelled(job_id):
                log_fp.write(f"\nMigration cancelled by user during {phase}.\n")
                if key_path and os.path.exists(key_path):
                    try:
                        os.remove(key_path)
                    except Exception:
                        pass
                return True
            return False
        log_fp.write(f"Starting Server Replication Job #{job_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        log_fp.write(f"Source Server: {ip}:{port}\n")
        log_fp.write(f"Active Admin Session Key: {admin_session_key}\n")
        log_fp.write(f"Active User Session Key: {user_session_key}\n")
        log_fp.write(f"Items Selected: {len(users)} users, {len(domains)} domains, {len(databases)} databases\n\n")

        # 1. Setup Key File
        if auth_method == 'key':
            log_fp.write("Writing secure temporary private key file...\n")
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

        # Fetch remote OLSPanel base directory dynamically
        remote_base_dir = "/usr/local/olspanel/mypanel"
        dir_res = run_ssh_command("sudo cat /etc/olspanel/base_dir")
        if dir_res.returncode == 0 and dir_res.stdout.strip():
            remote_base_dir = dir_res.stdout.strip()

        # 2. Replicate Linux System Users
        log_fp.write("==================================================\n")
        log_fp.write("Phase 1: Replicating Linux System Users\n")
        log_fp.write("==================================================\n")
        
        for u in users:
            if check_cancellation("Phase 1 (User replication)"): return
            username = u.get('username')
            password_hash = u.get('password_hash', '')
            is_superuser = u.get('is_superuser', False)
            email = u.get('email', '')

            log_fp.write(f"Processing user '{username}'...\n")

            # Get user shell and home path from source passwd
            pwd_res = run_ssh_command(f"getent passwd {username}")
            if pwd_res.returncode != 0:
                log_fp.write(f"User '{username}' passwd not found on source server. Skipping Linux account setup.\n")
                continue

            # Format: username:x:uid:gid:gecos:home:shell
            pwd_parts = pwd_res.stdout.strip().split(':')
            if len(pwd_parts) < 7:
                log_fp.write(f"Failed to parse passwd info for user '{username}'. Skipping Linux account setup.\n")
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
                log_fp.write(f"System user '{username}' already exists locally. Updating home directory and shell...\n")
                subprocess.run(["usermod", "-s", shell, "-d", home_dir, username])
            else:
                # Create user
                create_cmd = ["useradd", "-m", "-s", shell, "-d", home_dir]
                if remote_shadow_hash:
                    # Create with encrypted password hash
                    create_cmd += ["-p", remote_shadow_hash]
                create_cmd.append(username)

                log_fp.write(f"Creating system user '{username}' locally...\n")
                res = subprocess.run(create_cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    log_fp.write(f"Failed to create system user '{username}': {res.stderr}\n")
                else:
                    log_fp.write(f"Successfully created system user '{username}'.\n")

            # Ensure OLS traversal permissions for home directory (711)
            if os.path.exists(home_dir):
                subprocess.run(["chmod", "711", home_dir])

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
                log_fp.write(f"Django database user record synced for '{username}'.\n")
            except Exception as e:
                log_fp.write(f"Warning syncing Django user record: {str(e)}\n")

            # Replicate the user's password file (for auto-login / file manager access)
            for file_prefix in ["_", "phpmyadmin_"]:
                remote_pf = f"{remote_base_dir}/etc/{file_prefix}{username}"
                pwd_file_res = run_ssh_command(f"sudo cat {remote_pf}")
                if pwd_file_res.returncode == 0:
                    local_pf = os.path.join(settings.BASE_DIR, 'etc', f"{file_prefix}{username}")
                    try:
                        os.makedirs(os.path.dirname(local_pf), exist_ok=True)
                        with open(local_pf, 'w') as f:
                            f.write(pwd_file_res.stdout)
                        log_fp.write(f"Synced auto-login credentials file '{file_prefix}{username}'.\n")
                    except Exception as fe:
                        log_fp.write(f"Warning writing credentials file locally: {str(fe)}\n")

        # 2b. Synchronize PHP Versions & Extensions
        log_fp.write("\n==================================================\n")
        log_fp.write("Phase 1b: Synchronizing PHP Versions & Extensions\n")
        log_fp.write("==================================================\n")
        
        try:
            # Detect remote OS package manager
            log_fp.write("Detecting package manager on source server...\n")
            remote_is_rhel = False
            rpm_check = run_ssh_command("which rpm")
            if rpm_check.returncode == 0:
                remote_is_rhel = True
                log_fp.write("Source server detected as RHEL-based (CentOS/AlmaLinux/Rocky).\n")
            else:
                log_fp.write("Source server detected as Debian/Ubuntu-based.\n")

            # Detect local OS package manager
            local_is_rhel = False
            if os.path.exists('/usr/bin/dnf') or os.path.exists('/usr/bin/yum') or os.path.exists('/usr/sbin/dnf'):
                local_is_rhel = True
                log_fp.write("Destination server detected as RHEL-based (CentOS/AlmaLinux/Rocky).\n")
            else:
                log_fp.write("Destination server detected as Debian/Ubuntu-based.\n")

            # Fetch packages from source
            if remote_is_rhel:
                pkg_cmd = "rpm -qa --qf '%{NAME}\\n' 'ls-php*'"
            else:
                pkg_cmd = "dpkg-query -f '${binary:Package}\\n' -W 'lsphp*'"
            
            log_fp.write("Checking installed PHP packages on source server...\n")
            pkg_res = run_ssh_command(pkg_cmd)
            
            packages_to_install = []
            if pkg_res.returncode == 0:
                for line in pkg_res.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith('dpkg-query:') and 'dpkg-query:' not in line:
                        # Convert package names if source and destination OS types differ
                        if remote_is_rhel and not local_is_rhel:
                            # Convert e.g. ls-php81-mysql to lsphp81-mysql
                            line = line.replace('ls-php', 'lsphp')
                        elif not remote_is_rhel and local_is_rhel:
                            # Convert e.g. lsphp81-mysql to ls-php81-mysql
                            line = line.replace('lsphp', 'ls-php')
                        packages_to_install.append(line)
            
            if packages_to_install:
                log_fp.write(f"Found {len(packages_to_install)} PHP packages to sync: {', '.join(packages_to_install)}\n")
                if local_is_rhel:
                    log_fp.write("Installing PHP packages locally via dnf/yum...\n")
                    pm_bin = "dnf" if os.path.exists('/usr/bin/dnf') or os.path.exists('/usr/sbin/dnf') else "yum"
                    install_cmd = ["sudo", pm_bin, "install", "-y"] + packages_to_install
                else:
                    log_fp.write("Running apt-get update locally on destination server...\n")
                    subprocess.run(["sudo", "apt-get", "update", "-y"], capture_output=True)
                    log_fp.write("Installing PHP packages locally via apt...\n")
                    install_cmd = ["sudo", "apt-get", "install", "-y"] + packages_to_install

                inst_res = subprocess.run(install_cmd, capture_output=True, text=True)
                if inst_res.returncode == 0:
                    log_fp.write("PHP packages and extensions successfully synchronized.\n")
                else:
                    log_fp.write(f"Warning: Some PHP packages failed to install: {inst_res.stderr.strip()}\n")
            else:
                log_fp.write("No LiteSpeed PHP packages found on the source server.\n")
        except Exception as e:
            log_fp.write(f"Warning synchronizing PHP packages: {str(e)}\n")

        # 2c. Synchronize Node.js Versions
        try:
            log_fp.write("\nChecking installed Node.js versions on source server...\n")
            node_check_cmd = "[ -d /usr/local/olspanel/bin/nodejs ] && ls -1 /usr/local/olspanel/bin/nodejs || true"
            node_res = run_ssh_command(node_check_cmd)
            
            node_versions = []
            if node_res.returncode == 0:
                for line in node_res.stdout.splitlines():
                    line = line.strip()
                    if line and line.isdigit():
                        node_versions.append(line)
            
            if node_versions:
                log_fp.write(f"Found {len(node_versions)} Node.js versions on source: {', '.join(node_versions)}\n")
                for version in node_versions:
                    if not os.path.exists(f"/usr/local/olspanel/bin/nodejs/{version}"):
                        log_fp.write(f"Installing Node.js version {version} locally...\n")
                        node_install_res = subprocess.run(["sudo", "bash", "/usr/local/olspanel/mypanel/etc/install_node_versions.sh", "install", version], capture_output=True, text=True)
                        if node_install_res.returncode == 0:
                            log_fp.write(f"Node.js version {version} successfully installed.\n")
                        else:
                            log_fp.write(f"Warning: Failed to install Node.js version {version}: {node_install_res.stderr.strip()}\n")
                    else:
                        log_fp.write(f"Node.js version {version} is already installed locally.\n")
            else:
                log_fp.write("No Node.js versions found on the source server.\n")
        except Exception as e:
            log_fp.write(f"Warning synchronizing Node.js versions: {str(e)}\n")

        # 3. Synchronize Web Directories (Rsync)
        log_fp.write("\n==================================================\n")
        log_fp.write("Phase 2: Transferring Web Content & Files\n")
        log_fp.write("==================================================\n")

        for d in domains:
            if check_cancellation("Phase 2 (File transfer)"): return
            domain_name = d.get('domain')
            owner = d.get('username')
            source_path = d.get('path', f'/home/{owner}/{domain_name}')

            log_fp.write(f"Syncing website files for '{domain_name}'...\n")
            
            # Skip file transfer if the source path does not exist on the remote server
            # (e.g. system control panel virtual host configurations or directories that aren't on disk)
            remote_dir_check = run_ssh_command(f"[ -d '{source_path}' ]")
            if remote_dir_check.returncode != 0:
                log_fp.write(f"Skipping file transfer: directory '{source_path}' does not exist on source server.\n")
                continue
            
            # Resolve destination path dynamically matching source folder configuration
            dest_path = f"/home/{owner}/{domain_name}"
            if source_path.endswith('/public_html'):
                dest_path = f"/home/{owner}/public_html"
            elif source_path.endswith('/public_htm'):
                dest_path = f"/home/{owner}/public_htm"
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
            
            log_fp.write(f"Running rsync file transfer (silent mode, compression={'ON' if compress_transfer else 'OFF'})...\n")
            log_fp.write("Syncing files ")
            
            # Run rsync
            rsync_proc = subprocess.Popen(rsync_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Print a status tick and check cancellation every 5 seconds
            last_tick = time.time()
            while rsync_proc.poll() is None:
                if time.time() - last_tick >= 5:
                    if is_job_cancelled(job_id):
                        log_fp.write("\nMigration cancelled. Terminating active rsync process...\n")
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
                log_fp.write(f"File transfer complete. Adjusting file permissions for {owner}...\n")
                subprocess.run(["chown", "-R", f"{owner}:{owner}", dest_path])
            else:
                log_fp.write(f"File transfer failed with code {rsync_proc.returncode}.\n")

            # Replicate Let's Encrypt SSL folder if present
            log_fp.write(f"Checking SSL certificates for '{domain_name}'...\n")
            # Use sudo to check /etc/letsencrypt permission-restricted folder on remote
            ssl_check_cmd = f"sudo [ -d /etc/letsencrypt/live/{domain_name} ] && echo 'SSL_EXISTS'"
            ssl_res = run_ssh_command(ssl_check_cmd)
            if 'SSL_EXISTS' in ssl_res.stdout:
                log_fp.write(f"Copying Let's Encrypt SSL folders for '{domain_name}'...\n")
                
                # Delete existing directories/symlinks to avoid rsync write conflicts
                import shutil
                for local_dir in [f"/etc/letsencrypt/live/{domain_name}", f"/etc/letsencrypt/archive/{domain_name}"]:
                    if os.path.exists(local_dir) or os.path.islink(local_dir):
                        try:
                            if os.path.islink(local_dir):
                                os.unlink(local_dir)
                            else:
                                shutil.rmtree(local_dir)
                        except Exception as de:
                            log_fp.write(f"Warning clearing directory {local_dir}: {str(de)}\n")

                # Create local SSL directories
                os.makedirs(f"/etc/letsencrypt/live/{domain_name}", exist_ok=True)
                os.makedirs(f"/etc/letsencrypt/archive/{domain_name}", exist_ok=True)
                os.makedirs(f"/etc/letsencrypt/renewal", exist_ok=True)

                # Sync live, archive, and renewal config
                rsync_ssl_args = ["rsync", "-avz"]
                if ssh_username != 'root':
                    rsync_ssl_args += ["--rsync-path=sudo rsync"]

                cmd_live = rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/live/{domain_name}/", f"/etc/letsencrypt/live/{domain_name}/"]
                cmd_archive = rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/archive/{domain_name}/", f"/etc/letsencrypt/archive/{domain_name}/"]
                cmd_renewal = rsync_ssl_args + ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:/etc/letsencrypt/renewal/{domain_name}.conf", f"/etc/letsencrypt/renewal/{domain_name}.conf"]

                if auth_method == 'password':
                    cmd_live = ["sshpass", "-e"] + cmd_live
                    cmd_archive = ["sshpass", "-e"] + cmd_archive
                    cmd_renewal = ["sshpass", "-e"] + cmd_renewal

                subprocess.run(cmd_live, env=env)
                subprocess.run(cmd_archive, env=env)
                subprocess.run(cmd_renewal, env=env)
                
                # Fix symlinks inside letsencrypt/live/ which might be broken by rsync
                # Only convert to symlink if the corresponding archive file exists.
                # If the source certs are regular files (e.g. from acme.sh), we keep them as regular files.
                live_dir = f"/etc/letsencrypt/live/{domain_name}"
                for file_name in ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']:
                    link_path = os.path.join(live_dir, file_name)
                    archive_target_abs = f"/etc/letsencrypt/archive/{domain_name}/{file_name}"
                    if os.path.exists(archive_target_abs):
                        archive_target_rel = f"../../archive/{domain_name}/{file_name}"
                        if os.path.islink(link_path):
                            try:
                                if os.readlink(link_path) != archive_target_rel:
                                    os.unlink(link_path)
                                    os.symlink(archive_target_rel, link_path)
                            except Exception:
                                pass
                        else:
                            if os.path.exists(link_path):
                                os.remove(link_path)
                            os.symlink(archive_target_rel, link_path)
                
                log_fp.write(f"SSL Certificate files successfully synced.\n")

        # 4. Synchronize Databases & Users (MySQL)
        log_fp.write("\n==================================================\n")
        log_fp.write("Phase 3: Copying & Restoring Databases\n")
        log_fp.write("==================================================\n")

        # 4a. Replicate MySQL database users and grants
        log_fp.write("Fetching database users and grants from source...\n")
        
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
                log_fp.write("Restoring database users and grants locally...\n")
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
                        log_fp.write("Database user credentials synced successfully.\n")
                    else:
                        # Fallback try executing line-by-line ignoring errors
                        log_fp.write("Direct SQL grants import warning: trying line-by-line fallback...\n")
                        with connection.cursor() as cursor:
                            for line in grants_sql.split('\n'):
                                if line.strip() and not line.startswith('--'):
                                    try:
                                        cursor.execute(line)
                                    except Exception:
                                        pass
                        log_fp.write("Database credentials migration fallback executed.\n")
                    os.remove(sql_temp_path)
                except Exception as e:
                    log_fp.write(f"Warning migrating database users/grants: {str(e)}\n")
        else:
            log_fp.write("Could not read MySQL user list from source. Database connections may require manual setups if database users differ from site users.\n")

        # 4b. Replicate Databases
        local_mysql_pass = get_local_mysql_password()

        # Save active sessions (admin and user) from being lost if local panel database gets overwritten
        admin_session_data_dict = None
        if admin_session_key:
            log_fp.write(f"Attempting to back up active admin session key '{admin_session_key}'...\n")
            try:
                from django.contrib.sessions.backends.db import SessionStore
                s = SessionStore(session_key=admin_session_key)
                if s.exists(admin_session_key):
                    admin_session_data_dict = dict(s.items())
                    log_fp.write(f"Admin session data backed up successfully. Keys present: {list(admin_session_data_dict.keys())}\n")
                else:
                    log_fp.write(f"Warning: admin session '{admin_session_key}' does not exist in database.\n")
            except Exception as se:
                log_fp.write(f"Note: failed to capture active admin session dict: {str(se)}\n")
        else:
            log_fp.write("No active admin session key provided. Skipping admin session backup.\n")

        user_session_data_dict = None
        if user_session_key:
            log_fp.write(f"Attempting to back up active user session key '{user_session_key}'...\n")
            try:
                from django.contrib.sessions.backends.db import SessionStore
                s = SessionStore(session_key=user_session_key)
                if s.exists(user_session_key):
                    user_session_data_dict = dict(s.items())
                    log_fp.write(f"User session data backed up successfully. Keys present: {list(user_session_data_dict.keys())}\n")
                else:
                    log_fp.write(f"Warning: user session '{user_session_key}' does not exist in database.\n")
            except Exception as se:
                log_fp.write(f"Note: failed to capture active user session dict: {str(se)}\n")
        else:
            log_fp.write("No active user session key provided. Skipping user session backup.\n")

        for db_name in databases:
            if check_cancellation("Phase 3 (Database replication)"): return
            log_fp.write(f"Replicating database '{db_name}'...\n")
            log_fp.write(f"WARNING: This will overwrite/drop local tables in '{db_name}'. If the site is already live here, it may experience temporary query errors during the import.\n")
            
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
            
            log_fp.write("Streaming dump & restore pipeline...\n")
            try:
                # Add 30-minute timeout to prevent infinite socket hangs at scale
                # Pass password securely via env variables in shell environment
                res = subprocess.run(dump_restore_cmd, shell=True, env=env, capture_output=True, text=True, timeout=1800)
                if res.returncode == 0:
                    log_fp.write(f"Database '{db_name}' successfully imported.\n")
                else:
                    log_fp.write(f"Database '{db_name}' import failed: {res.stderr}\n")
            except subprocess.TimeoutExpired:
                log_fp.write(f"Database '{db_name}' import timed out (exceeded 30 mins).\n")

        # 5. Sync OpenLiteSpeed configs & Django records
        log_fp.write("\n==================================================\n")
        log_fp.write("Phase 4: Rebuilding OpenLiteSpeed Configs & Panel metadata\n")
        log_fp.write("==================================================\n")

        for d in domains:
            if check_cancellation("Phase 4 (OLS Config sync)"): return
            domain_name = d.get('domain')
            owner = d.get('username')
            # Resolve doc_root path dynamically matching source structure
            doc_root = f"/home/{owner}/{domain_name}"
            source_path = d.get('path', f'/home/{owner}/{domain_name}')
            if source_path.endswith('/public_html'):
                doc_root = f"/home/{owner}/public_html"
            elif source_path.endswith('/public_htm'):
                doc_root = f"/home/{owner}/public_htm"

            log_fp.write(f"Synchronizing OLS Vhost configurations for '{domain_name}'...\n")
            
            # Sync OLS Vhost config folder
            vhost_src = f"/usr/local/lsws/conf/vhosts/{domain_name}/"
            vhost_dest = f"/usr/local/lsws/conf/vhosts/{domain_name}/"
            
            os.makedirs(vhost_dest, exist_ok=True)
            ssh_rsync_opts = f"ssh -p {port} -o StrictHostKeyChecking=no"
            if key_path:
                ssh_rsync_opts += f" -i {key_path}"

            rsync_opts = ["rsync", "-avz"]
            if ssh_username != 'root':
                rsync_opts.append("--rsync-path=sudo rsync")
            rsync_opts += ["-e", ssh_rsync_opts, f"{ssh_username}@{ip}:{vhost_src}", vhost_dest]
            
            subprocess.run(rsync_opts)
            subprocess.run(["chown", "-R", "lsadm:lsadm", vhost_dest])

            # Apply virtual host mapping inside destination's httpd_config.conf
            try:
                registered = register_domain_in_httpd_config(domain_name, doc_root)
                if registered:
                    log_fp.write(f"Mapped '{domain_name}' to OpenLiteSpeed httpd_config.conf.\n")
                else:
                    log_fp.write(f"'{domain_name}' already declared in httpd_config.conf.\n")
            except Exception as e:
                log_fp.write(f"Failed mapping '{domain_name}' to OpenLiteSpeed config: {str(e)}\n")

            # Create Domain Metadata in OLSPanel Database
            try:
                user_obj = User.objects.filter(username=owner).first()
                domain_obj, created = Domain.objects.get_or_create(
                    domain=domain_name,
                    defaults={
                        'userid': user_obj,
                        'path': doc_root,
                        'php': '8.1',
                        'ssl_exp': 'Not Available',
                        'line': 0
                    }
                )
                if created:
                    log_fp.write(f"Registered '{domain_name}' metadata in OLSPanel dashboard records.\n")
                else:
                    log_fp.write(f"'{domain_name}' already exists in panel database.\n")
            except Exception as e:
                log_fp.write(f"Warning adding domain metadata to DB: {str(e)}\n")

        # Self-healing Django migrations handler
        log_fp.write("\nSyncing panel database migrations & running self-healer...\n")
        try:
            # Pre-emptively fix any database column mismatches from older source databases
            try:
                from django.db import connection
                with connection.cursor() as cursor:
                    # Check users_profile columns
                    cursor.execute("SHOW COLUMNS FROM users_profile LIKE 'pkg_id'")
                    if not cursor.fetchone():
                        try:
                            cursor.execute("ALTER TABLE users_profile ADD COLUMN pkg_id INT DEFAULT NULL;")
                            log_fp.write("Added missing 'pkg_id' column to 'users_profile' table.\n")
                        except Exception:
                            pass

                    # Check user_settings columns
                    cursor.execute("SHOW COLUMNS FROM user_settings LIKE 'hour_maximum_backup'")
                    if not cursor.fetchone():
                        columns_to_add = [
                            "hour_maximum_backup INT DEFAULT 24",
                            "day_maximum_backup INT DEFAULT 100",
                            "week_maximum_backup INT DEFAULT 50",
                            "month_maximum_backup INT DEFAULT 12"
                        ]
                        for col in columns_to_add:
                            try:
                                cursor.execute(f"ALTER TABLE user_settings ADD COLUMN {col};")
                                log_fp.write(f"Added missing user_settings column: {col}\n")
                            except Exception:
                                pass
            except Exception as dbe:
                log_fp.write(f"Note: pre-emptive column check: {str(dbe)}\n")

            # We run migrations in a separate subprocess to avoid Django thread deadlocks or connection pooling conflicts
            python_bin = "/root/venv/bin/python" if os.path.exists("/root/venv/bin/python") else "python3"
            manage_py = "/usr/local/olspanel/mypanel/manage.py"
            if not os.path.exists(manage_py):
                manage_py = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "manage.py")

            # Pre-emptively generate missing migration files for file_manager
            subprocess.run([python_bin, manage_py, "makemigrations", "file_manager", "--noinput"], capture_output=True)

            # Try normal migrate
            migrate_res = subprocess.run([python_bin, manage_py, "migrate", "--noinput"], capture_output=True, text=True)
            if migrate_res.returncode == 0:
                log_fp.write("Migrations completed successfully.\n")
            else:
                err_str = migrate_res.stderr
                log_fp.write(f"Migration error detected: {err_str.strip()}\n")
                
                # Check for packages/users.0005 table conflict
                if "packages" in err_str or "pkg_id" in err_str or "users.0005" in err_str:
                    # Manually add the missing pkg_id column to users_profile if not present
                    from django.db import connection
                    with connection.cursor() as cursor:
                        try:
                            cursor.execute("ALTER TABLE users_profile ADD COLUMN pkg_id INT DEFAULT NULL;")
                            log_fp.write("Successfully added missing 'pkg_id' column to 'users_profile' table.\n")
                        except Exception:
                            pass
                    
                    # Fake migrate users 0005
                    log_fp.write("Faking migration 'users.0005_package_profile_pkg_id_domain_dns_record'...\n")
                    fake_res = subprocess.run([python_bin, manage_py, "migrate", "users", "0005_package_profile_pkg_id_domain_dns_record", "--fake", "--noinput"], capture_output=True, text=True)
                    if fake_res.returncode == 0:
                        log_fp.write("Faked users.0005 successfully.\n")
                        # Retry general migrate
                        retry_res = subprocess.run([python_bin, manage_py, "migrate", "--noinput"], capture_output=True, text=True)
                        if retry_res.returncode == 0:
                            log_fp.write("Migrations successfully resolved and completed.\n")
                        else:
                            log_fp.write(f"Migration retry failed: {retry_res.stderr.strip()}\n")
                    else:
                        log_fp.write(f"Failed to fake users.0005: {fake_res.stderr.strip()}\n")
                
                # Check for user_settings/file_manager conflict
                elif "user_settings" in err_str:
                    from django.db import connection
                    with connection.cursor() as cursor:
                        columns_to_add = [
                            "hour_maximum_backup INT DEFAULT 24",
                            "day_maximum_backup INT DEFAULT 100",
                            "week_maximum_backup INT DEFAULT 50",
                            "month_maximum_backup INT DEFAULT 12"
                        ]
                        for col in columns_to_add:
                            try:
                                cursor.execute(f"ALTER TABLE user_settings ADD COLUMN {col};")
                                log_fp.write(f"Added missing user_settings column: {col}\n")
                            except Exception:
                                pass
                    
                    fake_res = subprocess.run([python_bin, manage_py, "migrate", "file_manager", "--fake", "--noinput"], capture_output=True, text=True)
                    if fake_res.returncode == 0:
                        log_fp.write("Faked file_manager successfully.\n")
                        retry_res = subprocess.run([python_bin, manage_py, "migrate", "--noinput"], capture_output=True, text=True)
                        if retry_res.returncode == 0:
                            log_fp.write("Migrations successfully resolved and completed.\n")
                        else:
                            log_fp.write(f"Migration retry failed: {retry_res.stderr.strip()}\n")
                    else:
                        log_fp.write(f"Failed to fake file_manager: {fake_res.stderr.strip()}\n")
                        
                # Check for apps/users.0006+ conflicts
                elif any(tbl in err_str for tbl in ["apps", "app_settings", "backup", "bandwidth", "blocked_ip"]):
                    fake_res = subprocess.run([python_bin, manage_py, "migrate", "users", "--fake", "--noinput"], capture_output=True, text=True)
                    if fake_res.returncode == 0:
                        log_fp.write("Faked users migrations successfully.\n")
                        retry_res = subprocess.run([python_bin, manage_py, "migrate", "--noinput"], capture_output=True, text=True)
                        if retry_res.returncode == 0:
                            log_fp.write("Migrations successfully resolved and completed.\n")
                        else:
                            log_fp.write(f"Migration retry failed: {retry_res.stderr.strip()}\n")
                    else:
                        log_fp.write(f"Failed to fake users: {fake_res.stderr.strip()}\n")
        except Exception as e:
            log_fp.write(f"Warning syncing database migrations: {str(e)}\n")

        # Close all current Django connections to clear any stale cache or transaction isolation states
        try:
            from django.db import connections
            for conn in connections.all():
                conn.close()
        except Exception as ce:
            log_fp.write(f"Note: connection close warning: {str(ce)}\n")

        # Restore active admin session to the panel database if it was overwritten
        if admin_session_key and admin_session_data_dict:
            log_fp.write(f"Attempting to restore active admin session key '{admin_session_key}'...\n")
            try:
                from django.contrib.sessions.backends.db import SessionStore
                
                user_id = admin_session_data_dict.get('_auth_user_id')
                user = None
                if user_id:
                    user = User.objects.filter(id=user_id).first()
                if not user:
                    # Fallback to username 'admin' or first superuser if ID differs/missing
                    user = User.objects.filter(username='admin').first() or User.objects.filter(is_superuser=True).first()
                    if user:
                        admin_session_data_dict['_auth_user_id'] = str(user.id)
                        log_fp.write(f"Mapped session user ID to active admin ID: {user.id}\n")
                
                if user:
                    admin_session_data_dict['_auth_user_hash'] = user.get_session_auth_hash()
                    log_fp.write("Recalculated session authentication hash for admin session.\n")
                
                s_new = SessionStore(session_key=admin_session_key)
                s_new.clear()
                for k, v in admin_session_data_dict.items():
                    s_new[k] = v
                s_new.save()
                log_fp.write("Preserved and authenticated active admin session successfully.\n")
            except Exception as se:
                import traceback
                log_fp.write(f"Warning restoring active admin session:\n{traceback.format_exc()}\n")
        else:
            log_fp.write("Skipping admin session restore (not active or missing backup).\n")

        # Restore active user session to the panel database if it was overwritten
        if user_session_key and user_session_data_dict:
            log_fp.write(f"Attempting to restore active user session key '{user_session_key}'...\n")
            try:
                from django.contrib.sessions.backends.db import SessionStore
                
                user_id = user_session_data_dict.get('_auth_user_id')
                user = None
                if user_id:
                    user = User.objects.filter(id=user_id).first()
                if not user:
                    user = User.objects.filter(username='admin').first() or User.objects.filter(is_superuser=True).first()
                    if user:
                        user_session_data_dict['_auth_user_id'] = str(user.id)
                
                if user:
                    user_session_data_dict['_auth_user_hash'] = user.get_session_auth_hash()
                
                s_new = SessionStore(session_key=user_session_key)
                s_new.clear()
                for k, v in user_session_data_dict.items():
                    s_new[k] = v
                s_new.save()
                log_fp.write("Preserved and authenticated active user session successfully.\n")
            except Exception as se:
                import traceback
                log_fp.write(f"Warning restoring active user session:\n{traceback.format_exc()}\n")
        else:
            log_fp.write("Skipping user session restore (not active or missing backup).\n")

        # Reload OpenLiteSpeed to apply configurations
        log_fp.write("\nReloading OpenLiteSpeed web server...\n")
        subprocess.run(["/usr/local/lsws/bin/lswsctrl", "reload"])
        log_fp.write("OpenLiteSpeed reloaded.\n")

        # Job Completed Successfully
        completed_at = datetime.now()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE replicator_jobs SET status = 'completed', completed_at = %s WHERE id = %s", [completed_at, job_id])
        
        log_fp.write(f"\nServer Migration Replication completed successfully at {completed_at.strftime('%Y-%m-%d %H:%M:%S')}!\n")
    
    except Exception as err:
        completed_at = datetime.now()
        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE replicator_jobs SET status = 'failed', completed_at = %s WHERE id = %s", [completed_at, job_id])
        except Exception:
            pass

        if log_fp:
            log_fp.write(f"\nMigration Failed with unexpected error: {str(err)}\n")
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
