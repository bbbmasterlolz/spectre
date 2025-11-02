import os
import shutil

repo_url = "https://github.com/candrawijayaa/ML_IDS.git"
folder = "ML_IDS"

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
else:
    print(f"Operation failed (exit code {result}).")
