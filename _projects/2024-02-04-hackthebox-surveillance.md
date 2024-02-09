---
layout: post
title: "HackTheBox: Surveillance"
image: /assets/thumbnails/surveillance-thumbnail.png
---

> This is the walkthrough of the machine Surveillance on HackTheBox. Coming very soon!

---

First, we do an Nmap service and version scan. We find that SSH is running on port 22/TCP and also 1 HTTP ports - 80/TCP. 
Also, the target host is UNIX-based.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~]
└─$ <span class="highlight-command">nmap -sV -sC 10.10.11.245</span>
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-04 13:33 EST
Nmap scan report for 10.10.11.245
Host is up (0.081s latency).
Not shown: 905 closed tcp ports (conn-refused), 92 filtered tcp ports (no-response)
PORT     STATE SERVICE         VERSION
<span class="highlight-output">22/tcp   open  ssh             OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)</span>
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.57 seconds
	</code>
</pre>

<figure>
  <figcaption>Enumerating the open ports and listening services using Nmap.</figcaption>
</figure>


<figure>
  <figcaption>Enumerating the open ports and listening services using Nmap.</figcaption>
</figure>


