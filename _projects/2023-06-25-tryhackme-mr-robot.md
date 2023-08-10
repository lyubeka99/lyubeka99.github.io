---
layout: post
title: "TryHackMe: Mr. Robot"
image: /assets/thumbnails/mr-robot-thumbnail.png
---

> This is the walkthrough of the machine Mr. Robot on TryHackMe. It is an easy challenge that involves some clever enumeration, vulnerability and exploit research and some clever Linux privilege escalation technique. Definitely a fun box for beginners.

---

## Enumeration

Starting the VM, we are greeted by a login prompt, asking for credentials. We do not have any yet. A quick nmap scan reveals the following:

![nmap](/assets/img/projects-img/mr-robot-nmap.PNG){: class="center-image"}