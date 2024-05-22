---
title: "Write-up: Stoopid's 'nano'"
description: "A write-up for a crackme involving assembly level obfuscation and cross process fault handling."
date: 2024-05-21
categories: ["Write-Ups", "CrackMes"]
tags: [crackmes.one, stoopid]
---

This is my solution to the "nano" crackme which was created by Stoopid for 0xL4ugh CTF 2024. You can find it on [crackmes.one](https://crackmes.one/crackme/65e5f417199e6a5d372a4045).

## Step 1: Just run it
After just running `./nano` we are greeted with a nice usage text:
```console
> ./nano
usage: ./nano <flag>
```

Ok so then lets just try giving it some random string to see how it behaves:

```console
> ./nano test
no
```

Since there is not much more here to see, let's load it into Ghidra.

## Step 2: A first look in Ghidra
Loading it into Ghidra we see a large main function. Ignoring a bunch of unreadable code we are left with this:

```c
int main(int argc, char** argv, char** envp, char param_4) {
    // declarations and initializations

    if (argc != 2) {
        printf("usage: %s <flag>\n", argv[0]);
        exit(1);
    }
    pid = fork();
    if (pid == 0) {
        // a bunch of unreadable code

        if (check(argv[1]) == 0) {
            puts("yes");
        } else {
            puts("no");
        }
        exit(0);
    }
    // a bunch of unreadable code
}
```

This seems to suggest that we only need to look at the `check` function to see how the flag is validated, so let's do that:

```c
undefined4 check(char *param_1) {
    size_t sVar1;
    byte local_1d;
    undefined4 local_1c;
    
    sVar1 = strlen(param_1);
    local_1c = 0;
    local_1d = 0;
    while( true ) {
        if (0x23 < local_1d) {
            return local_1c;
        }
        if ((int)sVar1 < (int)(uint)local_1d) break;
        if ((char)(KEY[(int)(uint)local_1d] ^ param_1[local_1d]) != flag[(int)(uint)local_1d]) {
            local_1c = 1;
        }
        local_1d = local_1d + 1;
    }
    return 1;
}
```

Ok not very readable, let's clean that up a little bit:

```c
int check(char *input) {
    size_t length;
    byte i;
    int wrong;
    
    length = strlen(input);
    wrong = false;
    for (int i = 0; i <= 35; i++) {
        if (i > length) return 1;
        if ((char)(KEY[i] ^ input[i]) != flag[i]) {
          wrong = true;
        }
    }
    return wrong;
}
```

Ok so it seems like the input is verified by xor encrypting it with `KEY` and comparing the result to the xor encrypted flag.
Since xor encryption and decryption are equivalent, we can just take the cipher text in `flag` and decrypt it using `KEY`.
And now we have our flag:

> watch : https://youtu.be/dQw4w9WgXcQ

Hmm suspicicous you should take a look at that video, I will try validating it with the binary:

```console
> ./nano 'watch : https://youtu.be/dQw4w9WgXcQ'
no
```

Ok that was to be expected, let's keep investigating.

## Step 3: GDB

To get a better idea of what happens in the check function, let's load it into gdb (with [pwndbg](https://pwndbg.re)) and see what happens exactly happens there:

```console
> gdb ./nano
> set follow-fork-mode child  # set gdb to follow the child process on a fork() call
> start test
> b check                     # set a breakpoint at check()
> continue
```

Now gdb should stop execution at the beginning of a call to `check`. Stepping through the function one instruction at a time, we find the following instruction which is executed right before the segfault:

```asm
mov r11, qword ptr [0]
```

Ok that is weird, there is no circumstance under which this shouldn't lead to a segfault, yet when we executed the binary without gdb and with the same input, no segfault occured.

It seems we will have to look at all of that unreadable code in `main` afterall.

## Step 4: Deobfuscating main

Looking at the `main` function more closely, the first thing I notice is these weird if statements all over the place:

```c
if ((!bVar11) && (bVar11)) {
    // more code
}
```

That looks very suspicious, so let's look at the assembly code that leads to this decompilation error:

|  address   |      bytes       |              instruction               |
|------------|------------------|----------------------------------------|
| `001012d2` | `89 45 f8`       | `MOV  dword ptr [RBP + local_10], EAX` |
| `001012d5` | `83 7d f8 00`    | `CMP  dword ptr [RBP + local_10], 0x0` |
| `001012d9` | `75 6c`          | `JNZ  LAB_00101347`                    |
| `001012db` | `74 03`          | `JZ   0x001012e0`                      |
| `001012dd` | `75 01`          | `JNZ  0x001012e0`                      |
| `001012df` | `e8 48 c7 c7 00` | `CALL SUB_00d7da2c`                    |
| `001012e4` | `00 00`          | `ADD  byte ptr [RAX],AL`               |
| `001012e6` | `00 48 8b`       | `ADD  byte ptr [RAX + -0x75],param_4`  |

Looking at these instructions, we can see that there are three jump instructions after another. The latter two jump to the same address and each tests the exact negation of the other's condition. Looking at the address they jump to, ghidra seems to think it is _in the middle of an instruction?_

This is because Ghidra assumes that the third conditional jump may not trigger a jump and therefore it concludes that the first byte after it must be the first byte of an instruction.

Since _we_ know that it will always jump, we can easily remove this type of obfuscation by replacing the five involved bytes (two bytes per jump and one garbage byte that is skipped by the jumps) with two NOP instructions, as you can see here:

|  address   |         bytes          |              instruction              |
|------------|------------------------|---------------------------------------|
| `001012d2` | `89 45 f8`             | `MOV dword ptr [RBP + local_10], EAX` |
| `001012d5` | `83 7d f8 00`          | `CMP dword ptr [RBP + local_10], 0x0` |
| `001012d9` | `75 6c`                | `JNZ LAB_00101347`                    |
| `001012db` | `66 48 90`             | `NOP`                                 |
| `001012de` | `48 90`                | `NOP`                                 |
| `001012e0` | `48 c7 c7 00 00 00 00` | `MOV argc,0x0`                        |
| `001012e7` | `48 8b ...`            | `...`                                 |

Having fixed one of these is great, but it would be nice to find and fix all of them and be done with this obfuscation. Luckily the jumps are relative, meaning it is likely the obfuscator used the same bytes everytime.

Searching the program memory for the four bytes that make up the jump instructions (`74 03 75 01`), we can indeed find more occurences of this type of obfuscation. After patching all of these out, the decompiler output already looks a LOT better:

```c
int main(int argc,char **argv,char **envp,int param_4) {
    int result;
    undefined4 in_register_0000000c;
    undefined auStack_108 [24];
    ulong uStack_f0;
    long lStack_88;
    uint local_24;
    undefined *puStack_20;
    byte local_11;
    __pid_t pid;
    uint uStack_c;
    
    uStack_c = 0;
    if (argc != 2) {
        printf("usage: %s <flag>\n",*argv,envp,CONCAT44(in_register_0000000c,param_4));
        exit(1);
    }
    pid = fork();
    if (pid != 0) {
        func_00101189(0x10,CONCAT44(uStack_c,pid),0,0);
        while (waitpid(pid,(int *)&local_24,0), (local_24 & 0x7f) != 0) {
            if (local_24 != 0xffff) {
                if (((local_24 & 0xff) == 0x7f) && ((local_24 & 0xff00) == 0xb00)) {
                    uStack_c = uStack_c + 1;
                    local_11 = ((char)uStack_c * '\b' ^ 0xcaU | (byte)((int)uStack_c >> 5)) ^ 0xfe;
                    puStack_20 = auStack_108;
                    func_00101189(0xc,CONCAT44(uStack_c,pid),0,puStack_20);
                    uStack_f0 = (ulong)local_11 | 0x7ffc9286a800;
                    lStack_88 = lStack_88 + 8;
                    puStack_20 = auStack_108;
                    func_00101189(0xd,CONCAT44(uStack_c,pid),0,puStack_20);
                }
                func_00101189(7,CONCAT44(uStack_c,pid),0,0);
            }
        }
        return 0;
    }
    func_00101189(0,(ulong)uStack_c << 0x20,0,0);
    result = check(argv[1]);
    if (result == 0) {
        puts("yes");
    } else {
        puts("no");
    }
    exit(0);
}
```

> Since we are modifying the binary, we will have to make sure to validate the flag with the original unmodifed file.
{: .prompt-warning}

Now that the cpde isn't wrong anymore, it is time to understand what it does.

## Step 5: Understanding the behaviour of the parent process

As we can see the `main` function branches into two parts after a `fork` of the process, meaning the first part is executed by the parent process, while the second part is executed by the child process.

Looking at the parent process code we see a bunch of calls to `func_00101189`, so let's take a look at that function.

The decompiler output is relatively useless here, but the disassembly speaks volumes:

```nasm
MOV  qword ptr [RBP + local_20],RDI # unnecessary
MOV  qword ptr [RBP + local_28],RSI # unnecessary
MOV  qword ptr [RBP + local_30],RDX # unnecessary
MOV  qword ptr [RBP + local_38],RCX # unnecessary
MOV  RAX,0x4f
MOV  RDI,qword ptr [RBP + local_20] # unnecessary
MOV  RSI,qword ptr [RBP + local_28] # unnecessary
MOV  RDX,qword ptr [RBP + local_30] # unnecessary
NOP                                 # result of our deobfuscation
NOP                                 # result of our deobfuscation
XOR  RAX,0x2a
MOV  R10,qword ptr [RBP + local_38]
SYSCALL
MOV  RAX,RAX                        # unnecessary
MOV  qword ptr [RBP + local_10],RAX # unnecessary
MOV  RAX,qword ptr [RBP + local_10] # unnecessary
```

I have marked a bunch of instructions in there that are unneccessary to understanding the function. And with those marked, the purpose of the method becomes relatively obvious: It makes a syscall and returns the result. Looking up what syscall the id `0x2a` belongs to, we can now update the functions signature with the following result:

```c
long ptrace(long request,long pid,void *addr,void *data) {
    return syscall();
}
```

Knowing the purpose of this function and having corrected its signature, we can go back and take another look at `main`. Looking at it now, the next thing we need to find out is what ptrace requests are actually happening there. Luckily Ghidra has a really nice feature called "Equate" using this we get a list of C macros with the same value. Searching those for "ptrace" we can quickly identify all the names for them:

```c
int main(int argc,char **argv) {
    int result;
    undefined auStack_108 [24];
    ulong uStack_f0;
    long lStack_88;
    int wstatus;
    undefined *puStack_20;
    byte local_11;
    __pid_t pid;
    uint uStack_c;
    
    uStack_c = 0;
    if (argc != 2) {
        printf("usage: %s <flag>\n",*argv);
        exit(1);
    }
    pid = fork();
    if (pid != 0) {
        ptrace(PTRACE_ATTACH,CONCAT44(uStack_c,pid),(void *)0x0,(void *)0x0);
        while (waitpid(pid,(int *)&wstatus,0), (wstatus & 0x7f) != 0) {
            if (wstatus != 0xffff) {
                if (((wstatus & 0xff) == 0x7f) && ((wstatus & 0xff00) == 0xb00)) {
                    uStack_c = uStack_c + 1;
                    local_11 = ((char)uStack_c * '\b' ^ 0xcaU | (byte)((int)uStack_c >> 5)) ^ 0xfe;
                    puStack_20 = auStack_108;
                    ptrace(PTRACE_GETREGS,CONCAT44(uStack_c,pid),(void *)0x0,puStack_20);
                    uStack_f0 = (ulong)local_11 | 0x7ffc9286a800;
                    lStack_88 = lStack_88 + 8;
                    puStack_20 = auStack_108;
                    ptrace(PTRACE_SETREGS,CONCAT44(uStack_c,pid),(void *)0x0,puStack_20);
                }
                ptrace(PTRACE_CONT,CONCAT44(uStack_c,pid),(void *)0x0,(void *)0x0);
            }
        }
        return 0;
    }
    ptrace(PTRACE_TRACEME,(ulong)uStack_c << 0x20,(void *)0x0,(void *)0x0);
    result = check(argv[1]);
    if (result == 0) {
        puts("yes");
    } else {
        puts("no");
    }
    exit(0);
}
```
> If Ghidra doesn't let you set an Equate, try to set it on the value in the Assembly listing and re-create the function.
{: .prompt-tip}

Looking at this now, it appears that the parent process waits for status changes in the child and then, if some conditions apply, modifies the register contents before continuing the child process.

Looking at the man page for `waitpid` (`man 2 waitpid`) tells us that the `wstatus` result is interpreted via macros which can be found in the `sys/wait.h` file. Considering the definitions in that header file and its dependencies, this is what the original C code most likely looked like:

```c
ptrace(PTRACE_ATTACH,pid,(void *)0x0,(void *)0x0);
while (waitpid(pid, &wstatus, 0), WTERMSIG(wstatus) != 0) {
    if (!WIFCONTINUED(wstatus)) {
        if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSEGV) {
            // register modification code
        }
        ptrace(PTRACE_CONT,pid,(void *)0x0,(void *)0x0)
    }
}
```
> The `SIGSEGV` macro is included via `signal.h`.
{: .prompt-info}

Looking at this the general behaviour of the parent process should be easy to understand: It waits until the child process is stopped, modifies its registers only if it was stopped because of a segfault (remember that weird instruction that always triggers a segfault? That seems to trigger this handler) and continues its execution again.

We can also take a look at the man page for `ptrace` (`man 2 ptrace`) and update some types to end up with the following:

```c
segfault_cnt++;
override = ((char)segfault_cnt * '\b' ^ 0xcaU | (byte)((int)segfault_cnt >> 5)) ^ 0xfe;
ptrace(PTRACE_GETREGS,pid,(void *)0x0,&user_regs);
user_regs.r12 = (ulong)override | 0x7ffc9286a800;
user_regs.rip = user_regs.rip + 8;
ptrace(PTRACE_SETREGS,pid,(void *)0x0,&user_regs);
```

So from this it seems like on every segfault the `R12` register of the child process is set to a new value and the Program Counter / Return Instuction Pointer Register is increased by 8, mostly likely to skip an instruction to prevent the child process from segfaulting again.

## Step 6: Understanding the check function

Now let's try to understand what that those register modifications are doing by looking closer at the `check` function where the segfault is caused:

|  address   |           bytes           |             instruction / comment              |
|------------|---------------------------|------------------------------------------------|
|            |                           | Load the value at `KEY[i]` into R12D           |
| `00101206` | `0f b6 45 eb`             | `MOVZX length,byte ptr [RBP + i]`              |
| `0010120a` | `48 98`                   | `CDQE`                                         |
| `0010120c` | `48 8d 15 8d 2e 00 00`    | `LEA   RDX,[KEY]`                              |
| `00101213` | `0f b6 04 10`             | `MOVZX length,byte ptr [length + RDX]=>KEY`    |
| `00101217` | `0f b6 c0`                | `MOVZX length,length`                          |
| `0010121a` | `41 89 c4`                | `MOV   R12D,length`                            | 
|            |                           | Trigger segfault                               |
| `0010121d` | `4c 8b 1c 25 00 00 00 00` | `MOV   R11,qword ptr [DAT_00000000]`           |
|            |                           | Load the value at `flag[i]` into `local_25`    |
| `00101225` | `0f b6 45 eb`             | `MOVZX length,byte ptr [RBP + i]`              |
| `00101229` | `48 98`                   | `CDQE`                                         |
| `0010122b` | `48 8d 15 2e 2e 00 00`    | `LEA   RDX,[flag]`                             |
| `00101232` | `0f b6 04 10`             | `MOVZX length,byte ptr [length + RDX]=>flag`   |
| `00101236` | `88 45 e3`                | `MOV   byte ptr [RBP + local_25],length`       |
|            |                           | Load the value at `input2[i]` into EDX         |
| `00101239` | `0f b6 55 eb`             | `MOVZX EDX,byte ptr [RBP + i]`                 |
| `0010123d` | `48 8b 45 d8`             | `MOV   length,qword ptr [RBP + input2]`        |
| `00101241` | `48 01 d0`                | `ADD   length,RDX`                             |
| `00101244` | `0f b6 00`                | `MOVZX length,byte ptr [length]`               |
| `00101247` | `89 c2`                   | `MOV   EDX,length`                             |
|            |                           | XOR the input and KEY values                   |
| `00101249` | `44 89 e0`                | `MOV   length,R12D`                            |
| `0010124c` | `31 d0`                   | `XOR   length,EDX`                             |
| `0010124e` | `88 45 e2`                | `MOV   byte ptr [RBP + local_26],length`       |
| `00101251` | `0f b6 45 e2`             | `MOVZX length,byte ptr [RBP + local_26]`       |
|            |                           | Compare XOR result to flag value and jump      |
| `00101255` | `3a 45 e3`                | `CMP   length,byte ptr [RBP + local_25]`       |
| `00101258` | `74 07`                   | `JZ    LAB_00101261`                           |

As we can see, the Segfault instruction is exactly eight bytes long, which lines up nicely with the eight byte increase of the program counter in the segfault handler, which therefore exactly skips that instruction.

We can also see that the byte loaded from `KEY` is loaded into `R12D` meaning that it is overwritten by the segfault handler which is triggered by the instruction at `0010121d`.

In conclusion this means the check iterates over the input, xors it with the characters generated by the segfault handler and compares the result to the hardcoded encrypted flag.

From here we can extract the flag by extracting the generated key bytes and then using those the same way we did in the naive approach to the check function.

## Step 7: Getting the Flag

To extract the key bytes we can simply put a breakpoint where the `R12` register is overwritten and take the value from the `EAX` register when the breakpoint hits.

(Make sure to start it with input that is long enough, otherwise the loop in check will end early)

Doing that we get a list of values like these:

```
0x7ffc9286a83c
0x7ffc9286a824
0x7ffc9286a82c
0x7ffc9286a814
...
0x7ffc9286a83d
0x7ffc9286a825
0x7ffc9286a82d
0x7ffc9286a815
```

Since these are not one byte each we need to know which byte is xored with the input. Looking at the instructions from the check function, we can see that the last byte of the xored value is moved onto the stack and back. Therefore we know that only the last byte of those values is relevant. If we truncate the extracted values accordingly, we get a list of of values like these:

```
0x3c
0x24
0x2c
0x14
...
0x3d
0x25
0x2d
0x15
```

Xoring these with the encrypted flag, we get the unencrypted flag:

> 0xL4ugh{3z_n4n0mites_t0_g3t_st4rt3d}

Which we can validate on the unpatched binary like so:

```console
> ./nano 0xL4ugh{3z_n4n0mites_t0_g3t_st4rt3d}
yes
```