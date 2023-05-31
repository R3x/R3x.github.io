---
title: "Exec System Call"
date: 2023-5-30 23:43:10  
tags: ["Systemcalls", "Linux"]
author: "Siddharth Muralee"
category: "Linux System calls"
params:
    ShowBreadCrumbs: true
    ShowShareButtons: true
    ShowPostNavLinks: true
    ShowCodeCopyButtons: true
ShowToc: true
---

# Exec System Call

Welcome to the first installment in a blog series that will takes a deep dive into the mechanics of system calls. Today, we're kicking things off with the exec system calls, a fundamental feature in Unix and Linux operating systems.

Glibc version used : 2.37 [Bootlin](https://elixir.bootlin.com/glibc/latest/source)


## Introduction to the exec library calls 

> **Note:** Please skip this section if you are already familiar with exec library calls.

In Unix and Linux systems, the `exec` family of library calls plays an essential role in process creation and management. While the general role of each function in the `exec` family is similar, they differ in how they accept arguments and in certain behaviors. These are the functions a user would typically use to interface with the kernel (exec syscall) to create a new process.

Here's an introduction to each member of the `exec` family:

**`execve`**: This function is the core of all `exec` functions, which all others essentially wrap around. It allows the specification of the argument list and environment variables. It is the only `exec` function that is a system call that interfaces directly with the kernel.

```c
char *args[] = {"ls", "-l", NULL};
char *env[] = {"PATH=/usr/bin", NULL};
execve("/bin/ls", args, env);
```

**`execl`**: This function takes a list of arguments individually, with the list terminated by a null pointer. It's handy when the number of parameters is known in advance. 

```c
execl("/bin/ls", "ls", "-l", NULL);
```

**`execv`**: This function takes an array of pointers to null-terminated strings that represent the argument list available to the new program. It's used when the number of parameters isn't known beforehand.

```c
char *args[] = {"ls", "-l", NULL};
execv("/bin/ls", args);
```

**`execle`**: This function is similar to `execl`, but it also allows the caller to specify the environment of the executed program.

```c
char *args[] = {"ls", "-l", NULL};
char *env[] = {"PATH=/usr/bin", NULL};
execle("/bin/ls", "ls", "-l", NULL, env);
```

**`execlp`, `execvp`, `execvpe` and `execlpe`**: These functions are similar to `execl` and `execv`, respectively. However, they use the `PATH` environment variable to find the program file to execute, which means you can use relative paths to executable files.

```c
char *args[] = {"ls", "-l", NULL};
char *env[] = {"PATH=/usr/bin", NULL};

execlp("ls", "ls", "-l", NULL);
// 
execvp("ls", args);
//
execvpe("ls", args, env);
// 
execlpe("ls", "ls", "-l", NULL, env);
// 
```

## Library to the Kernel - Invoking

The library calls can be found in the glibc source code, it's not a surprice that they are just wrappers for calling the kernel functions. All functions were found in the `posix` directory. 

For example, the `execv` function can be found in the `execv.c` file [Link](https://elixir.bootlin.com/glibc/latest/source/posix/execv.c#L23), and looks like this : 

```c
int
execv (const char *path, char *const argv[])
{
  return __execve (path, argv, __environ);
}
```

Let's now look at how __execve in implemented, and how it calls the system-call. It can be found in `execv.c` [Link](https://elixir.bootlin.com/glibc/latest/source/posix/execv.c#L26)

```c
int
__execve (const char *path, char *const argv[], char *const envp[])
{
  if (path == NULL || argv == NULL || envp == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }

  __set_errno (ENOSYS);
  return -1;
}
stub_warning (execve)

weak_alias (__execve, execve)
```

Wait! So how does it actually call the system call? Okay looks like we are gonna have to dig into how the glibc calls the system call. Let's look at both `stub_warning` and `weak_alias` functions.

### What is `stub_warning`?

`stub_warning` is a macro that is defined in `libc-symbols.h` [Link](https://elixir.bootlin.com/glibc/latest/source/include/libc-symbols.h#L225) and looks like this (with comments added to explain): 

```c
/* A canned warning for sysdeps/stub functions.  */
#define	stub_warning(name) \
  __make_section_unallocated (".gnu.glibc-stub." #name) \  
  link_warning (name, #name " is not implemented and will always fail") 

#define __make_section_unallocated(section_string)	\
  asm (".section " section_string "\n\t.previous");

#define link_warning(symbol, msg) \
  __make_section_unallocated (".gnu.warning." #symbol) \
  static const char __evoke_link_warning_##symbol[]	\
    __attribute__ ((used, section (".gnu.warning." #symbol __sec_comment))) \
    = msg;
```

For some context : 
* `.section` - This is a assembler directive to the assembler to switch to a different section. The section name is passed as an argument to the directive.
* `.previous` - This is a assembler directive to the assembler to switch back to the previous section.
  
So the `__make_section_unallocated` switches to a different section, and then has the `.previous` directive to switch back to the previous section. This is done to make sure that the section is not allocated in the final binary.

`link_warning(symbol, msg)`: This macro defines a string with a warning message (msg) that will be associated with the symbol. The string is placed in a special section (.gnu.warning.symbol) of the binary.

The idea here is that when the function (stub) is used, the linker will see the .gnu.warning.symbol section and output the warning message. This allows for a message to be shown at link time if a stub function is being used.


.... TODO: rest