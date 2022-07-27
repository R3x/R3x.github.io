---
title: "Digging into ELFs (Part 1)"
date: 2022-07-26 23:43:10  
tags: ["ELF", "RE"]
author: "Siddharth Muralee"
---

# Digging into ELFs (Part 1)

In this blog, I plan to look at the ELF file format, specifically the ELF headers, sections and segments.
This is gonna be a part of a series that I hope to complete part-by-part this month.

I am planning to use the [LIEF python module](https://github.com/lief-project/LIEF) to help me look at ELFs and understand what's happening.

## Overview

ELF file contains a header and data. The data is divided into segments, each segment can contian a number of sections. 

## The ELF Header

Each ELF file, contains a header - which is a collection of information about the ELF file. The following script can be used to view the header
of an ELF file. 

```python
import lief

binary = lief.parse("a.out")
print(binary.header)
```

This gives an output, which looks somewhat like this (I have added comments to make it understandable):
Also to mention things that are not shown

```
Magic:                           7f 45 4c 46   // ELF Magic Number
Class:                           CLASS64       // ELF Class (32 or 64)
Endianness:                      LSB           // ELF Endianness (LSB or MSB)
Version:                         CURRENT       // The only options are CURRENT and NONE
OS/ABI:                          SYSTEMV       // To determine the OS and ABI 
ABI Version:                     0             // To distinguish between different ABI versions (Find incompitability)
// IMP : There is typically a padding here of 0s and then a size variable, which is the size of all the fields above
File type:                       DYNAMIC       // This field shows whether the file is Executable, Relocatable, Shared or a Core dump file
Machine type:                    x86_64        // This is the Architecture of the file
// The above fields are printed in the order they are in the ELF file (modified the LIEF output)
Object file version:             CURRENT       // Another version thing, with the same two options as above
Entry Point:                     0x4192        // This is a **virtual address**, where the program should start executing
Program header offset:           0x64          // Offset to the program header (This is from the start of the file, so it's at 64(0x40 bytes))
Section header offset:           13968         // Offset to the section header (This is from the start of the file as well)
Processor Flag:                  0             // Processor flags, currenltly unused
Header size:                     64            // Size of the ELF header (Note that this is same as the Program header offset, they are adjacent)
Size of program header:          56            // Size of each program header entry
Number of program header:        13            // Number of program header entries
Size of section header:          64            // Size of each section header entry
Number of section headers:       31            // Number of section header entries
Section Name Table idx:          30            // Shows the index of the section name table (Normally one of the last sections)
```

The above table explains most of the fields in the ELF header.

The most important fields are the offsets to the program and section headers. Since these will be used to determine the sections that will be loaded into the address space. 

The LIEF module provides all the fields as class properties, which can be used to modify the header. The below python script does just that and creates a new ELF file.

```python

# Modify the ELF header
binary.header.entrypoint = 0xdeadbeef
binary.header.machine_type = lief.ELF.ARCH.AVR

# Write the modified ELF file
binary.write("modifued.elf)
```

## The Program Header

Each Program Header describes a segment or other information the system needs to prepare the program for execution.

As mentioned above, the header contains the offsets to the program header array. Each program header entry is a collection of mutliple values which is used to determine how the segment is leaded into the address space.

Let's take a look at the first segment using the LIEF module. This should be the segment which contains the ELF program header array.

```python
phdr_seg = binary.segments[0]
print(f"offset = {phdr_seg.file_offset}")
print(f"size = {phdr_seg.physical_size}")

```

This should give you the following output:
```python
offset = 64
size = 728
```

If you look at the offset you will discover that it's exactly the same as the size of the ELF header.
And the size is exactly same as the product of the number of program header entries and the size of each program header entry (Mentioned in the header above).

Each segment header consists of the following fields:
- Type : Determines what kind of segment it is, there are few possible types 
- 

<details>
  <summary>Click to expand!</summary>
  
  ## Heading
  Test
</details>






