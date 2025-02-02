+++
date = 2019-01-21T17:08:42-04:00
tags = ["re", "reverse engineering", "ctf", "rust", "binary ninja"]
category = ["Capture the Flag Writeups"]
draft = false
title = "Insomni'hack teaser 2019 CTF RE: beginner reverse writeup"
+++
## Challenge:
A babyrust to become a hardcore reverser.

The challenge provides us with a 64 bit Rust binary that we have to reverse engineer to get the flag.

## Solution:
We start by opening the binary in Binary Ninja. The function we are interested in is "beginer_reverse::main::h80fa15281f646bc1".

At the beginning of the function we see some values from the ".rodata" section being stored onto the stack. The "std::io::Stdin::read_line" function is called next to get our input.

![input comparison values and input length](/insomnihackteaser-2019-beginner_reverse-check-values.png)

Next the length of our input minus the newline character is calculated, and each character of our input is store in 32bit chunks on heap. Our input is then checked for non-ascii characters.

![check input for none-ascii characters](/insomnihackteaser-2019-beginner_reverse-loop2.png)

After the input has been checked for potential errors we get to algorithm that checks if we have entered the correct input (a.k.a. the flag). The length of the input is compared to the value located in at rsp+0x50 (this contains the value 0x22, 34 in decimal, that was stored on the stack at the beginning of the function). If the input length doesn't match this value the loop counter check will be set to the length of our input. This indicates that our input needs to be 34 characters long.

Next the function iterates over our input and and the values that were store on the stack at the beginning of the function. These value are divided by 4(sar edi, 2: an arithmetic shift right is equivalent to edi / 2²) and then xored with 0xa, the resulting value is then compared to our input one character at a time.

![check if we gave the right input](/insomnihackteaser-2019-beginner_reverse-loop3-mainlogic.png)

solution:
```C
#include <stdio.h>

int main() {
    int checkarray[] = {0x10e, 0x112, 0x166, 0x1c6, 0x1ce, 0xea, 0x1fe, 0x1e2,
                        0x156, 0x1ae, 0x156, 0x1e2, 0xe6, 0x1ae, 0xee, 0x156,
                        0x18a, 0xfa, 0x1e2, 0x1ba, 0x1a6, 0xea, 0x1e2, 0xe6,
                        0x156, 0x1e2, 0xe6, 0x1f2, 0xe6, 0x1e2, 0x1e6, 0xe6, 0x1e2, 0x1de};
    int len = 34;
    int result;

    printf("The flag is ");
    for (int i=0; i < len; i++) {
        result = checkarray[i] / 4;
        result = result ^ 0xa;
        printf("%c", result);
    }
    puts("\n");
}
```
flag:
```bash
$ ./solution
$ The flag is INS{y0ur_a_r3a1_h4rdc0r3_r3v3rs3r}
```
