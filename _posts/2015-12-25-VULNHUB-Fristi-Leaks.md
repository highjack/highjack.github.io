---
layout: post
title: VULNHUB - Fristi Leaks write up
tag: ctf
---

Yo, So it’s Christmas time and my life is temporarily calming down and just in time for me to enter this competition. It was pretty straight forward vulnerable web application, with some simple code review but now I’ve done it and I have some time, I thought I may aswell write it up. So this story starts the same way as every other pentest, conveniently for us, the IP address is provided by the VM itself.


Next up, let’s port scan it, the only port we find open is 80, we ran the scan with -sC to run some of the default nmap scripts and it discovers some weird entries in robots.txt, checking this out lead us to a dead end and we are shown some starwars meme image

If we actually look at the site, we see the following image:

This got me thinking, what the hell is a fristi ;/ So according to google it’s some kind of milkshake…

I ran dirbuster with no results, but eventually something clicked, so all the entries in robots were also drinks, so what if we try 192.168.56.101/fristi as a directory and BAM - here’s the admin panel!

I tried all the usual tests for SQL injection with no luck on this login page and then went back to scanning this particular directory with dirbuster

Cool, so it actually found something, “upload.php” looks tasty :)

So we check it out in burp, immediately I noticed that there was a location header redirecting us as away from the current page but I could still see the page contents, that looks like some broken access control if I ever did see it:

I just copied the form out into a file on my local apache:

and then opened it in my browser:

I played with the request for a few seconds because initially it blocked me uploaded a file with the name “shell.php”, I used a simple trick of double extensions which worked beautifully and called my file shell.php.jpg, I used it to upload the php-reverse-shell.php from kali’s webshells directory I just had to change the IP and port number in the config with burp:

In a terminal I launched netcat to listen on port 1337 and hit “forward” on burp, the response tells us that the file has been uploaded to /uploads. Atleast path disclosure bugs are useful ocassionally :)

Opening 192.168.56.101/fristi/uploads/shell.php.jpg I get a shiny new shell in netcat running as Apache:

Looking around the box a little I noticed a readable file in a user called eezeepz’s home directory at /home/eezeepz/notes.txt, apparently a user called admin has set up a cron job to read /tmp/runthis every minute, the cron will run will commands from /tmp/runthis aslong as the binaries are either in /usr/bin or /home/admin. The files in /home/admin are listed in the note:

We can easily use this to escalate our permissions to the admin user if we force the cron to use the cat command to copy /bin/dash to /tmp, which will ensure that the admin user owns the file followed by having the cron run chmod 4777 on the copied /bin/dash so that it will be executable by apache and will run as the admin user due to suid bit being set on /bin/dash:

As standard we want a truely interactive shell so we use python to spawn a real tty:

Inside /home/admin we find some interesting files, an encrypted password and a python script which encrypts user input using rot13 and base64:

We can now decrypt the password using a simple python script which just performs the reverse of cryptpass.py:



Decrypting the current user’s password probably isn’t so useful as we already have a shell running as their user. Looking around the box further, I noticed two things, there was also a file in /home/admin called whoisyourgodnow.txt which also contained what appeared to be another encrypted password and there is a user on the box called fristigod, on a hunch I wondered if this new text file might contain fristigod’s password:

I just used the su command to attempt to login as fristigod and it worked fine:

As fristigod, I checked out the output of sudo -l, they are allowed to run a binary called “doCom” as root but only as the fristi user (not fristigod) if we just run the command using sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom it works perfectly, the application says we need to provide a terminal command, so I just re-ran it with /bin/bash as an input, the result of this a root shell:

The flag file is shown below:

Thanks for reading my write up.
