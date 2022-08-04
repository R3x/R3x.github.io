---
title: "Digging into ELFs (Part 2)"
date: 2022-07-26 23:43:10  
tags: ["ELF", "RE"]
author: "Siddharth Muralee"
category: "Reversing"
params:
    ShowBreadCrumbs: true
    ShowPostNavLinks: true
ShowToc: true
---

# Digging into ELFs (Part 2)

Last time, I spent time looking at the ELF headers. And we got a decent idea of how the ELF file format stores data in various segments and sections. Now let's look deeper into different sections that are present in the ELF file.

## What are those various sections?

To view the sections using the LIEF python module, we can use the following script:

```python
import lief

binary = lief.parse("a.out")
for section in binary.sections:
    print(section)
```

Let's look at some of the sections:

Some of the more known ones are
- **.text** - This is the code section, where the opcodes for all the instructions are stored. This section is usually R and X (Read and Execute). 
- **.data** - This is the global data section, where all the initialized global variables and static variables of functions are stored. This section is usually R and W (Read and Write).
- **.rodata** - This is the read only data section, where all the constants are stored (Like strings for examples). This section is usually R (Read).
- **.bss** - This is the uninitialized data section. 

Other sections present

### .comment section

This section is used to store details about the ELF file. Such as information about the compiler etc.
This section can be really useful while reverse engineering, to extract information about the compiler that was used to compile the ELF file.

```python
if binary.has_section(".comment"):
    comment_sec = binary.get_section(".comment")
    print(comment_sec.content.to_bytes())
```

This gives the following output:

```
b'GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0\x00'
```

The above can be done using readelf as well:

```bash
r3x@pop ~/r/elf> readelf -p .comment ./a.out 

String dump of section '.comment':
  [     0]  GCC: (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

### .interp section

This section is used to store the name of the interpreter for the binary. 