---
layout: post
title: "HackTheBox: Busqueda"
image: /assets/thumbnails/busqueda-thumbnail.png
---

> This is the walkthrough of the machine Busqueda on HackTheBox. Coming soon!  

---
## Enumeration

Nmap shows port 80 HTTP open. When visiting `http://10.10.11.208:80/` we get redirected to searcher.htb. Since this is a CTF the domain name searcher.htb is not inserted in the global DNS so it cannot be resolved. To work around this, we can add the domain to our /etc/hosts file (I am working with a Linux based attacker host).

{% include explanation-box.html content="DNS (Domain Name System) is, generally speaking, a network of servers around the world that translates domain names (e.g Facebook.com) to numerical IP addresses. If a domain name isn't registered, we can use the /etc/hosts file (present in Linux based systems) to resolve a domain name to an IP address manually." %}

```
```