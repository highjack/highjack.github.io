---
layout: post
title: HTB - Mantis write up
---

Hey guys, so today I’m going to walk you through how I solved the Mantis box on hackthebox.org, it starts the same way most network pentests do, with an nmap scan…

As you can see below the results are pretty monsterous, but to summarize, we have a Windows DC (it’s running LDAP, Keberos etc) running Server 2008 R2, with SQL Server 2014 and two web servers, one on port 1337 and the other on 8080. I noted all of this down but from my experience people’s web applications are usually pretty weak so I started here, obviously the port 1337 appealed to me because it’s a non standard web port.

nmap -p- -A 10.10.10.52 -T4

```
Starting Nmap 7.60 ( https://nmap.org ) at 2018-02-22 18:41 GMT
Warning: 10.10.10.52 giving up on port because retransmission cap hit (1).
Stats: 0:03:00 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.92% done; ETC: 18:44 (0:00:00 remaining)
Nmap scan report for 10.10.10.52
Host is up, received echo-reply ttl 127 (0.030s latency).
Not shown: 64790 closed ports, 718 filtered ports
Reason: 64790 resets and 718 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Microsoft DNS 6.1.7601
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2018-02-22 18:42:06Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
1337/tcp  open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
1433/tcp  open  ms-sql-s     syn-ack ttl 127 Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: MANTIS
|   DNS_Domain_Name: htb.local
|   DNS_Computer_Name: mantis.htb.local
|_  Product_Version: 6.1.7601
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2018-02-22T18:34:17
|_Not valid after:  2048-02-22T18:34:17
|_ssl-date: 2018-02-22T18:43:11+00:00; -1s from scanner time.
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5722/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
8080/tcp  open  http         syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Tossed Salad - Blog
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49167/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49945/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
50255/tcp open  unknown      syn-ack ttl 127
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=2/22%OT=53%CT=1%CU=38061%PV=Y%DS=2%DC=T%G=Y%TM=5A8F0FB
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M54DNW8ST11%O2=M54DNW8ST11%O3=M54DNW8NNT11%O4=M54DNW8ST11%O5=M5
OS:4DNW8ST11%O6=M54DST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M54DNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2018-02-22T13:43:12-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2018-02-22 18:43:13
|_  start_date: 2018-02-22 18:33:49

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   28.30 ms 10.10.14.1
2   29.21 ms 
```
Looking at the site on 1337, we get a basic error page to tell us there is no page there, so we fire up dirsearch to bruteforce some content. I checked for txt, aspx (it’s windows!) and sql files. A little while later we find a folder called "secure_notes"

python3 dirsearch.py -w /usr/share/wordlist/dirbuster/directory-list-lower-2.3.medium.txt -e txt,aspx,sql -u http://10.10.10.52:1337



The first thing I noticed is that the file name for the txt file inside this folder was a base64 encoded value



But before we do I also checked out the contents of the note which gives us some valuable information that the “admin” user account exists for mssql and it’s used for the orchardcms database:



Decoding the base64 from the filename, gives us a hex value, if we decode this we get what looks like a password:



At this point we have a mssql user and what looks like a password so I used metasploit to try to enumerate mssql, which works fine:



I then used msf to query the database for a list of databases, as you can see we have there’s a database for orchardcms.



Next we modify our payload to grab the table names



then finally we grab the usernames and passwords, as you can see one of them appears to be plaintext:



I noticed when looking at the available msf scripts that you can query for Active Directory Users so I gave this a shot to see if the “James” user exists, which it did:


At this point I hit a brick wall for a while, so I started to search online for vulnerabilities that affect this version of Windows Server with the Services we found in the nmap, after a shortwhile I found the following link: https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/

If we try to use goldenpac from impacket we get our system shell:
