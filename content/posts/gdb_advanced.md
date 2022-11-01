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

Watchpoints are used to stop exectuing the program when a certain memory location is read/written. This is useful when you want to know when a certain variable is accessed. But you don't want to set a breakpoint on every single line where the variable may be accessed.

```gdb
(gdb) watch __afl_prev_loc
```

> Note: watchpoints can be called on any memory address, but you need to cast the address to help determine how many bytes need to be watched. For example, if you want to watch a 4 byte integer, you need to cast the address to `(int *)`
> ```bash
> (gdb) watch *(int *)0x7fffffffe3e0
> ```
> You need to use the `*` to dereference the address else gdb will try to watch the constant address itself.

- `watch` -  watchpoint for write access
- `rwatch` - watchpoint for read access
- `awatch` - watchpoint for read/write access

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

> Note: Sometimes if the type of the variable is not known you might have to cast it to the correct type, also useful if you are checking the value of a memory address for ex:
> 
> ```gdb
> (gdb) break __afl_maybe_log if (unsigned long)__afl_prev_loc == 0xdaef
> (gdb) break __afl_maybe_log if *(int *)($rbp - 0x10) == 0xdaef
> (gdb) break __afl_maybe_log if *(int *)0x7fffffffe0a0 == 0xdaef
> ```

if the breakpoint is already set, you can add a condition to it using the `condition` command:

```bash
(gdb) condition 1 $rcx == 0xdaef
```

and you can remove the condition using the command :

```bash
(gdb) condition 1
```

which resets the condition of the breakpoint.

You can also choose to ignore the breakpoint a certain number of times by using the `ignore` command:

```bash
(gdb) ignore 1 5
```

which will not stop at the breakpoint for the next 5 times, and then start stopping at the breakpoint again.


### Catchpoints

Another useful feature, especially when debugging multithreaded C++ applications is the `catch` command. It allows you to break the execution when a certain event occurs.

For ex, if I want to break when a thread is created, I can use the following command:

```bash
(gdb) catch thread create
```

Some common uses are :
- `catch syscall` : Break when a syscall is made
- `catch syscall <number/name>` : Break when a specific syscall is made
- `catch throw <regex>` : Break when a specific exception is thrown (C++)
- `catch catch <regex>` : Break when a specific exception is caught (C++)
- `catch signal <number/name>` : Break when a specific signal is sent
- `catch load/unload <regex>` : Break when a library is loaded/unloaded

### Custom commands

TODO: Briefly explain how to write custom commands

## GDB Python Scripting

GDB has a python scripting interface, which I have found to be useful exclusively for CTFs. I will try to quickly go over it, so that people can try it out for themselves.

Running a python script with gdb is as simple as running the following command:

```bash
gdb <target/executable> -x <path/to/script.py>
```

if you want to run a python script on a running gdb instance, you can use the `source` command:

```bash
(gdb) source <path/to/script.py>
```

### Defining custom commands in GDB

GDB allows you to define custom commands, in python. This is very useful to run a bunch of commands together and add some custom logic to it. 

```python
import gdb

class TestCommand(gdb.Command):
    def __init__(self):
        super(TestCommand, self).__init__("test", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        print("Test command invoked")
        counter = 0
        try:
            total_count = int(arg.split(" ")[0])
            skip_count = int(arg.split(" ")[1])
        except:
            print("Invalid arguments passed")
            return
        
        print(f"Total count: {total_count}")
        print(f"Skip count: {skip_count}")

        while counter < total_count:
            if counter % skip_count == 0:
                # Skip every skip count iteration
                gdb.execute("continue")
                continue
            
            gdb.execute("info registers")

            counter += 1
            gdb.execute("continue")

TestCommand()
```

The above script defines a custom command called `test` which takes 2 arguments - `total_count` and `skip_count`. The command will print the register values for every iteration, except for every `skip_count` iteration.


### Defining custom pretty printers

Say you have a struct defined as follows:

```c
struct Node {
    int value;
    struct Node *next;
};
```

While debugging, the program you wish to print the structure of the linked list. You can define a custom pretty printer to do that.

```python
TODO
```

### CTF challenge solving

I have used GDB python scripting to solve a few CTF challenges. It's a quick way to get some information from the binary, if you need to extract some runtime information.

For ex, here I am extracting characters which are generated during runtime, so that I can use them to reverse the encryption algorithm.

```python
TODO
```

## GDB Plugins

There are a lot of extensions available for GDB, which can make your life easier. 

### GEF

GEF is a GDB extension which adds a lot of useful features to GDB. It's a must have for CTFs. I will try to do another blog post on features specific to GEF that can be really helpful for CTFs.

### Decomp2dbg

This is a plugin which allows you to connect GDB to a decompiler. It's shows you the decompiled code in GDB, and allows you to set breakpoints in the decompiled code. It's extremely useful when you are debugging a binary without source code, and allows you to keep in sync with the decompiled code for faster debugging or reverse engineering.