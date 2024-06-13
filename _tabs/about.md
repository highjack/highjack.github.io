---
# the default layout is 'page'
icon: fas fa-info-circle
order: 3
layout: page
---

Yo, my name is highjack, or "Ben" in the meatspace. I’ve been interested in computers since the age of 6 when my parents bought me an Amiga 500 with a bunch of educational games, to "help me with my school work", or atleast that was the plan... 

When I got abit older my mum bought home her password protected Windows 95 work laptop. I was very curious about it but my mum did not want to share the password, so imagine my amazement when I found out I could just hit ESC to bypass the login. 

My interest in "Computer Security" was further encouraged after spending an unhealthy amount of time hanging out on hacking related Yahoo/MSN Chatrooms and learning about Remote Access Trojans such as Sub7 and Netbus. It was like the wild west back then, people would just port scan the whole of the AOL IP range and find preinfected machines, connect with the sub7 client and use the built in chat to talk to other script kiddies, but it was just that, script kiddie stuff. We were living a world where barely any end users had Anti Virus or Firewalls and those that did could be killed off pretty easily by just terminating a process, as they were just pieces of software running as a normal user. 

Poking around the internet lead me to sites like Astalavista, New Order, milw0rm and Phrack, I used these to learn more. When I started College at age 16, my friend convinced me to install Slackware on an old laptop, I used to have it hooked up to the phone line and would connect to IRC servers like dal.net, tddirc and efnet using the BitchX client. Times were very different back then, people would share web server 0days and remote file inclusion vulnerabilities in government websites, just to have bragging rights. 

We didn't have fancy online courses and videos, we shared txt files containing tutorials. People weren't into hacking because they heard someone tell them they could earn lots of money, everyone who was there was because they wanted to learn and they were curious by nature. 

I saw a bunch of people exploting websites with bugs like SQL injection, LFIs and RFIs and I wanted to be able to do that... I wanted to understand how software worked and make it do stuff it wasn't supposed to, it was cool. I decided to sit down and teach myself PHP, at this point getting paid to hack was completely unheard of but it didn't matter I was completely obessed with it. I figured atleast I'd have a fall back and I could become a web developer.

A lot of my online friends were avid C programmers and we spent alot of time playing CTFs like Smashthestack which was really fun. After a few years I finished Uni and became a PHP developer, but did do some small pentests for customers towards the end of my time there. I will never forget the first one, I was given a single IP address. I ran nmap against it and it had RDP and CCTV camera interface on port 8080. I opened the camera web interface and was prompted to run a Java Applet, I did so and poked through the settings, there was a starred out password there, I used some software called Asterisk Unhider, I guess it just reads the app memory to grab the actual string, I just used this to login to Domain Admin via RDP. I had heard of ethical hackers at this point but I assumed you would need some god like skill to get a job like that. Fortunately I was able to secure a junior role on an internal security team, I specialised in hacking websites but this very quickly expanded to mobile and I learnt alot about code review. Since then I have done  many different things and I am grateful for the experience. 

A few are note worthy areas are listed below:
- reverse engineering obfuscated code and malware (using IDA, Olly, Reflector/dnspy, jd-gui, Wireshark etc). 
- finding vulnerabilities and building exploits for in both internally developed, third party apps, appliances and even some hardware devices.
- Source code review for a bunch of languages such as: .NET, Go, python, javascript, C and Erlang.
- network pentesting and assumed breach scenarios

I used to hang out on vulnhub's IRC server and was invited to test the Offsec Proving Grounds beta, we only had a couple of weeks to look at it, but I would jump on in the morning before work, as soon as I got back from work and hack away at it til really late at night. I spent alot of time talking to TheColonial over this time and we pushed each other to try and finish as much of the lab before the time ran out. Offsec were so pleased by what we did they sent us Kali Challenge coins, I still have it today :D

There were a few Portswigger announcements on Twitter, users who came within their top 10 of their newly anounced labs would win some swag, this was done before any answers were available, so it was completely on us to find the solutions. I entered the events for XXE, SSRF and Access Control and each time won an item (a tshirt, a hoody and a backpack) it was really great.  

All these years later, this is still not "just a job" and I constantly strive to learn more, 99% of my learning takes place outside of work whether its from playing in a lab, reading articles, contributing to bug bounty programs when I have time (I don't mind recon but I am more of a deep dive kinda guy) or just taking something a part to see what it does. I am driven and I want to be the best I can possibly be, if I woke up tomorrow and was told being a professional security d00d was no longer an option, absolutely nothing would change. 

This site is pretty much just somewhere to dump notes and prove to people that I actually exist... hopefully something on here is useful to atleast one person, even if that's just to future me :) 

I'm not perfect so if you have any corrections that you think I should make feel free to @ me on twitter.

Lastly I'd like to dedicate this website to:
- My partner, our three awesome kids and my parents (I will keep their names hidden for privacy reasons) but I love you guys very much and I always will.
- My grandad Eric who always believed in me.
- One of my best friends Mike "Xirax" West who sadly passed away, you were an awesome hacker dude and I miss hacking with you everyday!

Cheers
