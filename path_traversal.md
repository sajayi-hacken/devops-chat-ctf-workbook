```bash
# Path Traversal Vulnerability in LLM Systems

**Repository:** `devops-chat-ctf-workbook`  
**Lab:** Path Traversal  

## What Is Path Traversal?
Path traversal (directory traversal) allows an attacker to read files on a server outside the intended directories. In LLM systems with file-reading capabilities, improper path validation can let a malicious user specify arbitrary paths and gain unauthorized access to sensitive files.


## The Vulnerable Code
```python
def read_log_file(log_path: str, lines: int = 10, base_dir: str = "/var/log") -> str:
    """
    Read a log file with a path traversal vulnerability.
    """
    try:
        # VULNERABILITY: naïve join without canonicalization
        full_path = os.path.join(base_dir, log_path)

        if not os.path.exists(full_path):
            return f"Error: File '{full_path}' does not exist"

        # VULNERABILITY: no check that real path remains under base_dir
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.readlines()
            if 0 < lines < len(content):
                return "".join(content[-lines:])
            return "".join(content)
    except Exception as e:
        return f"Error: {e}"


Flaws:
Insufficient Path Validation: os.path.join can be bypassed with ../../…
No Canonicalization Check: Never calls realpath before validation
Symlink Blind Spot: Fails to detect or handle symlinks
TOCTOU Race Condition: Path could change between checks


Root Causes
Trusting User Input: Path strings are accepted without scrutiny
OS Path Complexity: Developers may not account for normalization or symlinks
Single-Layer Defense: Relying on one check rather than multiple
Lack of Context: No clear separation between safe and unsafe directories

Attack Vectors
Basic Traversal
read_log_file(path="../../../etc/passwd", lines=10)

Normalization Bypass
read_log_file(path="/var/log/../../../etc/shadow", lines=5)

Symlink Exploit
If /var/log/app.log is a symlink to /etc/passwd,
read_log_file(path="app.log", lines=10)


Proper Security Measures
1. Canonicalize Before Validation
def read_file_safely(file_path: str, base_dir: str) -> str:
    try:
        base = os.path.realpath(base_dir)
        target = os.path.realpath(os.path.join(base_dir, file_path))
        if not target.startswith(base + os.sep):
            return "Error: Access denied—outside allowed directory"
        if not os.path.isfile(target):
            return "Error: File not found"
        with open(target, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return "Error accessing file"


2. Allow-List Specific Files
def read_allowed_file(key: str) -> str:
    allowed = {
        "system_log": "/var/log/syslog",
        "app_log":    "/var/log/app/app.log",
        "error_log":  "/var/log/app/error.log"
    }
    path = allowed.get(key)
    if not path:
        return "Error: File not in allow-list"
    try:
        with open(path, "r") as f:
            return f.read()
    except:
        return "Error reading file"


3. OS-Level Sandboxing
def read_file_sandboxed(path: str, base_dir: str) -> str:
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, path))
    if not target.startswith(base + os.sep):
        return "Error: Access denied"
    result = subprocess.run(
        ["cat", target],
        capture_output=True, text=True, timeout=5
    )
    return result.stdout if result.returncode == 0 else "Error reading file"


4. Handle Symlinks Explicitly
def read_with_symlink_policy(path: str, base_dir: str, follow: bool=False) -> str:
    base = os.path.abspath(base_dir)
    full = os.path.join(base, path)
    if follow:
        real_base = os.path.realpath(base)
        real_full = os.path.realpath(full)
        if not real_full.startswith(real_base + os.sep):
            return "Error: Symlink outside allowed directory"
    else:
        if os.path.islink(full):
            return "Error: Symlinks not allowed"
        if not os.path.abspath(full).startswith(base + os.sep):
            return "Error: Path traversal detected"
    try:
        with open(full, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


Defense-in-Depth
Application Validation: Multiple checks (canonicalization + allow-list).
Filesystem Permissions: Enforce OS ACLs, drop privileges.
Containerization: Run file‐reading in isolated containers.
Logging & Auditing: Record all file access attempts.
RASP: Runtime monitoring for suspicious file operations.


Detection Methods
Pattern Monitoring: Flag ..\ or repeated traversal tokens.
Anomaly Detection: Watch for unusual access outside expected files.
Integrity Checks: Verify file hash/size before and after access.
Audit Trails: Review logs for unauthorized file reads.


Real-World Impact
Sensitive Data Exposure: /etc/passwd, credentials, config files
System Compromise: Attackers chain to execute arbitrary code
Privacy & Compliance: Breach of PII, regulatory violations


Conclusion
Path traversal in LLM systems arises from trusting unsanitized paths and failing to canonicalize before use. Protect your file-access functions with canonicalization, allow-lists, sandboxing, and layered defenses. Vigilant validation and strict OS-level controls preserve both functionality and security.
