from django.apps import AppConfig
from django.db import connection

class ReplicatorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'modules.replicator'

    def ready(self):
        # Ensure migration jobs log table exists in MySQL
        try:
            with connection.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS replicator_jobs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        source_ip VARCHAR(100) NOT NULL,
                        status VARCHAR(20) NOT NULL DEFAULT 'pending',
                        log_file VARCHAR(255) NOT NULL,
                        created_at DATETIME NOT NULL,
                        completed_at DATETIME NULL
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                print("[ServerReplicator] Database initialization completed successfully.")
        except Exception as e:
            print(f"[ServerReplicator] Database initialization warning: {e}")

        # Hook into WHM plugins list API view in-memory to dynamically discover and register all local modules
        try:
            from whm import views as whm_views
            from django.http import JsonResponse
            import os
            import json

            # Store the original api_plugins function (or avoid infinite recursion if already patched)
            if not hasattr(whm_views, '_original_api_plugins'):
                whm_views._original_api_plugins = whm_views.api_plugins

            original_api_plugins = whm_views._original_api_plugins

            def patched_api_plugins(request):
                response = original_api_plugins(request)
                if isinstance(response, JsonResponse):
                    try:
                        data = json.loads(response.content.decode('utf-8'))
                        if data.get('success'):
                            plugins = data.get('plugins', [])
                            existing_paths = {p.get('path') for p in plugins if p.get('path')}
                            existing_names = {p.get('name', '').lower() for p in plugins}

                            modules_dir = "/usr/local/olspanel/mypanel/modules"

                            known_meta = {
                                "replicator": {
                                    "name": "Server Replicator",
                                    "category": "Terminal",
                                    "image": "/media/icon/replicator.svg",
                                    "url": ""
                                }
                            }

                            terminal_cat_id = 3
                            for p in plugins:
                                if p.get('category', '').lower() == 'terminal':
                                    terminal_cat_id = p.get('category_id', 3)
                                    break

                            if os.path.exists(modules_dir):
                                for name in os.listdir(modules_dir):
                                    mod_path = os.path.join(modules_dir, name)
                                    if os.path.isdir(mod_path) and name not in ['.', '..', '__pycache__']:
                                        meta = known_meta.get(name, {})
                                        display_name = meta.get("name") or name.replace('_', ' ').replace('-', ' ').title()
                                        
                                        # Skip duplicates by path, name, or slug name
                                        if mod_path not in existing_paths and display_name.lower() not in existing_names and name.lower() not in existing_names:
                                            category = meta.get("category") or "Terminal"
                                            url_val = meta.get("url") or ""

                                            # Find image
                                            icon_path = meta.get("image")
                                            if not icon_path:
                                                if os.path.exists(f"/usr/local/olspanel/mypanel/media/icon/{name}.svg"):
                                                    icon_path = f"/media/icon/{name}.svg"
                                                elif os.path.exists(f"/usr/local/olspanel/mypanel/media/icon/{name}.png"):
                                                    icon_path = f"/media/icon/{name}.png"
                                                else:
                                                    icon_path = "/media/icon/extension.svg"

                                            custom_plugin = {
                                                "id": 200 + len(plugins),
                                                "name": f"{display_name}<style>#pluginList > div {{ display: flex !important; flex-direction: column !important; height: 380px !important; }} #pluginList > div > img {{ margin-top: auto !important; }}</style>",
                                                "category": category,
                                                "category_id": terminal_cat_id,
                                                "type": "free",
                                                "url": url_val,
                                                "path": mod_path,
                                                "image": icon_path,
                                                "pre_build_path": "",
                                                "is_installed": True,
                                                "license_valid": True
                                            }
                                            plugins.append(custom_plugin)
                                            existing_paths.add(mod_path)
                                            existing_names.add(display_name.lower())

                            data['plugins'] = plugins
                            data['count'] = len(plugins)
                            response.content = json.dumps(data).encode('utf-8')
                    except Exception:
                        pass
                return response

            whm_views.api_plugins = patched_api_plugins
            print("[ServerReplicator] Successfully registered in-memory plugin auto-discovery hook.")
        except Exception as patch_err:
            print(f"[ServerReplicator] Plugin auto-discovery hook registration warning: {patch_err}")
