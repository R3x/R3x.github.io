---
title: "Digging into ELFs (Part 1)"
date: 2022-07-26 23:43:10  
tags: ["ELF", "RE"]
author: "Siddharth Muralee"
category: "Reversing"
params:
    ShowBreadCrumbs: true
    ShowShareButtons: true
    ShowPostNavLinks: true
    ShowCodeCopyButtons: true
ShowToc: true
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
- Type : Determines what kind of segment it is, there are few possible types (refer to the [Appendix below](#Elf-Segment-Types))
- Flags : Determines whether the segment is read, write, execute, etc.
- Offset : The offset **from the start of the file** to the segment.
- Virtual/Physical Address : Usually the same, determines the virtual address of the segment.
- alignment : alignment of the segments in the file. if it's 0/1 then it means there is no alignement. If it's 2^n then it means the segment is aligned to 2^n bytes.

**NOTE** : If a segment is loadable, then it should have consecutive virtual addresses with the previous and the next segments. 

Additionally, to view the program headers using objdump, you can use the following command:

```bash
objdump -l a.out 
```

## The Section Headers

A File also will contain a section header table, which will contain all the information about the sections inside the file. It is also an array of structures, with each structure representing a section.

The following fields are present in each section header:
- Name : Name of the section
- Type : Each section has a type, which helps determine how to handle it
- Flags : Determines things such as whether data is writable, whether it contains executable instructions etc.
- Address : The virtual address of where the section should be present if it's loaded into memory
- offset : The offset from the **start of the file** to the section
- 

```python
print(binary.sections[1])
```

which returns the following output (formatted and comments added to make it readable):
```python
.interp (Name)            
PROGBITS (Type : Here it means it was a section which holds information)
318 ((792 in decimal) Virtual Address : Note that the address is in hexadecimal)  
1c ((28 in decimal) size of the section in bytes) 
318 ((792 in decimal) Offset from the start of the file)
3.94076 (Entropy : This is not in the binary, but calculated by LIEF )
ALLOC  (Flags : Means the section is in memory)
INTERP LOAD (Segment Str : Type of Segments which holds this section, LIEF also prints this information)  
```

If you notice the offset, it's the same as the offset + the size of the program header, which is 792 bytes. This means it's adjacent to the program header table segment.

The segement string is calculated by LIEF in the following way:
```python
segments_str = " - ".join([str(s.type).split(".")[-1] for s in section.segments])
```

## Appendix

### ELF Segment Types 

(Copied from the man page)

- **PT_LOAD**
  The array element specifies a loadable segment,
  described by p_filesz and p_memsz.  The bytes
  from the file are mapped to the beginning of the
  memory segment.  If the segment's memory size
  p_memsz is larger than the file size p_filesz,
  the "extra" bytes are defined to hold the value
  0 and to follow the segment's initialized area.
  The file size may not be larger than the memory
  size.  Loadable segment entries in the program
  header table appear in ascending order, sorted
  on the p_vaddr member.
- **PT_DYNAMIC**
    The array element specifies dynamic linking
    information.
- **PT_INTERP**
  The array element specifies the location and
  size of a null-terminated pathname to invoke as
  an interpreter.  This segment type is meaningful
  only for executable files (though it may occur
  for shared objects).  However it may not occur
  more than once in a file.  If it is present, it
  must precede any loadable segment entry.
- **PT_NOTE**
  The array element specifies the location of
  notes (ElfN_Nhdr).
- **PT_SHLIB**
  This segment type is reserved but has
  unspecified semantics.  Programs that contain an
  array element of this type do not conform to the
  ABI.
- **PT_PHDR**
  The array element, if present, specifies the
  location and size of the program header table
  itself, both in the file and in the memory image
  of the program.  This segment type may not occur
  more than once in a file.  Moreover, it may
  occur only if the program header table is part
  of the memory image of the program.  If it is
  present, it must precede any loadable segment
  entry.
- **PT_LOPROC, PT_HIPROC**
  Values in the inclusive range [PT_LOPROC,
  PT_HIPROC] are reserved for processor-specific
  semantics.
- **PT_GNU_STACK**
  GNU extension which is used by the Linux kernel
  to control the state of the stack via the flags
  set in the p_flags member.

