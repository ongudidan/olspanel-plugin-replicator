# OLSPanel Server Replicator & Migration Wizard Plugin

An official plugin for **OLSPanel** to easily duplicate/replicate a remote OLSPanel server or selectively migrate websites, data directories, and databases between servers over a secure SSH connection.

## Features
- **Pull Migration Model**: Initiated directly from the fresh destination server, ensuring maximum reliability and resource isolation.
- **System Accounts Replication**: Fetches remote users, homes, shells, and shadow encrypted password hashes, recreating the Linux users on the local machine automatically.
- **Rsync File Transfers**: Uses fast, block-level differential `rsync` over SSH to copy web directory contents and Let's Encrypt SSL certificates.
- **Database Replicator**: Automates `mysqldump` and database user grant replication, cloning databases without manual credential matching.
- **Automatic OLS Mapping**: Appends virtual host config declarations to the destination's master `httpd_config.conf` listener blocks, registering them in OpenLiteSpeed instantly.
- **Dashboard Records Import**: Syncs Django database records (domains, users) to the local panel, displaying them in OLSPanel upon completion.
- **Live Terminal Console**: Interactive logging terminal streaming standard outputs in real-time.

## Requirements & Migration Flow

> [!IMPORTANT]
> **Read Before Deploying**:
> 1. **Destination Server Setup**: You must pre-install a fresh instance of **OLSPanel** on your new (destination) server. Keep it clean with no sites or databases configured.
> 2. **Where to Install**: Install this Replicator plugin on the **new (destination) server's OLSPanel**. It is not required to install it on the old source server.
> 3. **SSH Connectivity**: The new server must have SSH access to the old source server (authenticating via `root` SSH Private Key or Password).

## Installation

*Note: The command line installation instructions must be run with root/administrative privileges (e.g. prefix with `sudo` or run directly as root depending on your system configuration).*

### Method 1: Direct Command Line (Recommended)
You can install the latest release directly:
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-replicator/releases/latest/download/replicator.zip
```

Or target a specific version (e.g., `v1.0.0`):
```bash
install_cp_plugin https://github.com/ongudidan/olspanel-plugin-replicator/releases/download/v1.0.0/replicator_v1.0.0.zip
```

### Method 2: Manual Web UI
1. Go to the **Releases** page of this repository.
2. Download either the static `replicator.zip` or the version-specific `replicator_vX.Y.Z.zip` asset.
3. Log into your **OLSPanel Admin Control Panel**.
4. Go to **Plugins** -> **Install Plugin** and upload the downloaded zip.
5. Wait for the automatic reload to complete.

## Development & Packing
To pack the plugin manually, run this from the root of the repository:
```bash
zip -r replicator.zip replicator/ -x "*/.git*" -x "*.git*"
```

## Release Automation

### Option 1: Trigger via GitHub UI (Auto-increment)
1. Navigate to the **Actions** tab on GitHub.
2. Select the **Build and Release...** workflow.
3. Click the **Run workflow** button, select version level increment (`patch`, `minor`, `major`), and run.
4. The system will automatically compute the next version, tag it, and publish the release.

### Option 2: Manual Tag Push
If you prefer manual versioning:
```bash
git tag v1.0.0
git push origin v1.0.0
```
This triggers the Action to compile and publish that exact version.
