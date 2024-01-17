---
layout: post
title: "Review of Dante by HackTheBox"
---

> The beginner-friendly pro lab Dante is a failry new environment released by HackTheBox (HTB). The lab is quite big and serves well to practise certain penetration testing techniques even though
I found it to be unrealistic in terms of content and exploitation.

---

# Difficulty

Dante is one of the 6 pro lab environments offered on HTB as of the time of writing of this post. It is categorized as "Intermediate" although it is one of the easier pro labs.
There are 2 other labs - RastaLabs and Zephyr that are allegedly easier. I cannot speak to that fact since I haven't tried them. In any case, Dante is a good box for beginners with some 
knowledge of penetration testing tactics, techniques and procedures to practise their skills.

I personally decided to complete the lab as preparation for my Cetrified Penetration Testing Specialist (CPTS) exam. I would not recommend relying just on Dante for your CPTS preparation though.
Overall, the lab and the exam cover the same areas but the focus is quite different. More about that below.

In general, the lab is indeed beginner-friendly. I managed to solve it mostly on my own with the knowledge I obtained from the Penetration Tester job role path in HTB Academy. There is
one big exception though. One of the challenges within the lab was definitely a lot more difficult and I needed some help. Reflecting back on it, I would have never been able to do it on my
own. I though this was a bit out of place in such a lab. But apart from that particular part, I did not need any additional or more advanced techniques than those taught in the job role path.

# Content

The lab consists of 14 total machines and requires players to capture 26 flags to pass. As the lab itself advertises, the main areas of focus are:

* Enumeration
* Exploit Development
* Lateral Movement
* Privilege Escalation
* Web Application Attacks

I would also add a little bit of local buffer overflow attacks and a very petite Active Directory (AD) network. 

However, some of these are more heavily covered than others. For example, reaching some subnets requires a ridiculous amount of pivoting and certainly the web attacks are the most widespread
challenge within the lab. Overall, the lab is structured more like a collection of individual machines than a realistic corporate network (with minor exceptions). For those of you who don't
know how HackTheBox machines operate - usually you find some RCE vulnerability and find a user flag after exploiting it, then you need some privilege escalation to gain root (or 
NT AUTHORITY/SYSTEM for Windows) access and you find the root flag.

Furthermore, the lab is structured a lot like a Capture the Flag (CTF) exercise and is not very realistic. Solving some boxes certainly requires information to be gathered from pevious boxes
but in a way that you would not find realistic corporate evnironments do.

# The Cons?

Overall, I think any additional exercise is always good for upskilling. And while Dante definitely covers some key areas of the offensive toolset, it lacks heavily in others. Therefore,
I would recommend doing Dante as an exercise but also doing boxes/labs with more complex AD environments. The reason is that this is simply not Dante's main focus and if you really want to
learn how to approach testing AD, it is not ideal.

# Verdict

I think anyone trying to get into peneteration testing should have Dante on their roadmap at some point - either as a preparation for a certificate or simply harder challenges. However, it
should be something supplementary to your training, rather than a standard or a goal. Also, if you are a seasoned security professional with deep knowledge of penetration testing, I believe
that there are other, more challenging pro labs that you can get more out of.