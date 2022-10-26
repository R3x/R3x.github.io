---
title: "Advanced GDB Debugging"
date: 2022-10-25 23:43:10  
tags: ["Debugging", "GDB"]
author: "Siddharth Muralee"
category: "Debugging"
params:
    ShowBreadCrumbs: true
    ShowShareButtons: true
    ShowPostNavLinks: true
    ShowCodeCopyButtons: true
ShowToc: true
---

# Advanced GDB Debugging

In this post, I would like to point out some tips/tricks to make debugging easier with GDB. I will be focusing on Linux x86_64 binaries, but most of the things should work on other architectures as well. I will try to cover both 

I am gonna assume basic familiarity with GDB, such as setting breakpoints/stepping through code, etc. If you are not familiar with GDB, I would recommend reading/watching some basic tutorial for GDB.

## Using the .gdbinit file

Gdb uses a file called the `.gdbinit` file which is used to store all the settings needed when you start gdb. This can be configured on both a systemwide basis and also on a projectwide basis. The root `.gdbinit` is usually found in the `/home` directory, and the project specific `.gdbinit` is usually found in the root of the project directory. 

However to load a project specific .gdbinit file when you start gdb, you need to pass the following command to gdb:

```bash
gdb -x <path to .gdbinit file>
```

## GDB Advanced Commands

GDB has a lot of commands, I plan to try and cover the commands that helped me the most while debugging applications. A good starting tip - is that whenever you are stuck or can't remember the command that you were looking for, try using the `apropos` command. This is basically a regex search through the commands list and you can usually find the command you were looking for. To get more information about a command, use the `help` command.

### Watchpoints

Watchpoints are used to stop exectuing the program when a certain memory location is read/written. This is useful when you want to know when a certain variable is accessed.




### Conditional Breakpoints and Watchpoints
 
Conditional breakpoints are a amazing feature of GDB, which allows you to set a breakpoint only if a certain condition is met. This is very useful when you are debugging a basic block that's called multiple times, and you want to stop only when a certain condition is met.

For ex, if I want to stop at the call to __afl_maybe_log only if the the value of rcx is 0xdaef, I can use the following command:

```bash
(gdb) break __afl_maybe_log if $rcx == 0xdaef
```

If symbols are available, you can also have checks on condition on the values of variables. For ex, if I want to stop at the call to __afl_maybe_log only if the the value of __afl_prev_loc is 0xdaef, I can use the following command:

```bash
(gdb) break __afl_maybe_log if __afl_prev_loc == 0xdaef
```

> Note: Sometimes if the type of the variable is not known you might have to cast it to the correct type, for ex:
> 
> ```bash
> (gdb) break __afl_maybe_log if (unsigned long)__afl_prev_loc == 0xdaef
> ```