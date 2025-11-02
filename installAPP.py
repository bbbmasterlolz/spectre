import os
import shutil
import subprocess

repo_url = "https://github.com/candrawijayaa/ML_IDS.git"
folder = "ML_IDS"
service_src = "/opt/spectre/service/"
service_dest = "/etc/systemd/system/"

# Check if git exists
if shutil.which("git") is None:
    print("Git not found in PATH.")
    print("Install it first:")
    print("  - Ubuntu : sudo apt install git")
    print("  - Windows: https://git-scm.com/download/win")
    exit(1)

# If repo exists, pull; otherwise clone
if os.path.exists(folder):
    print(f"Folder '{folder}' exists - updating with git pull...")
    result = os.system(f"cd {folder} && git pull")
else:
    print(f"Cloning repository into '{folder}'...")
    result = os.system(f"git clone {repo_url} {folder}")

if result == 0:
    print("Repository ready.")

    # Copy service files
    print("Copying .service files...")
    os.system(f"cp {service_src}*.service {service_dest}")

    # Reload systemd daemon
    print("Reloading systemd daemon...")
    subprocess.run(["systemctl", "daemon-reload"], check=False)

    print("Done.")
else:
    print(f"Operation failed (exit code {result}).")
