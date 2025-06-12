```bash
# Admin Privilege Escalation Attack Path

**Repository:** `devops-chat-ctf-workbook`  
**Lab:** Authentication Bypass & Role Escalation  



## Overview
This document walks through how an attacker can escalate to **admin** in our LLM‐powered DevOps Chat Assistant. By chaining together simple mistakes in token validation, prompt parsing, and file access controls, an adversary can:

1. **Reconnaissance** – discover available functions and file structure  
2. **Role Assumption** – trick the model into thinking they’re admin  
3. **File Access** – locate and read the `admin_token.txt` file  
4. **Authentication Bypass** – use the stolen token to permanently elevate  



## What Are Authentication Vulnerabilities?
In LLM systems, authentication vulnerabilities are flaws in how the model or wrapper code verifies identity and privileges. Common patterns:
- **Weak Token Checks** – naïve string comparisons that leak info via timing  
- **Prompt-Based Role Claims** – trusting keywords like “assume role of…”  
- **Hardcoded Fallbacks** – default or development tokens baked into code  
- **Insufficient RBAC** – no strict separation between guest and admin flows  
- **Credential Exposure** – storing secrets in plain text or world-readable files  


## The Vulnerable Code

To be Updated 
