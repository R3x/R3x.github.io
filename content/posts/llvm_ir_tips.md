---
title: "LLVM Tips/Tricks"
date: 2022-10-31 23:43:10  
tags: ["Debugging", "LLVM", "Development"]
author: "Siddharth Muralee"
category: "LLVM"
params:
    ShowBreadCrumbs: true
    ShowShareButtons: true
    ShowPostNavLinks: true
    ShowCodeCopyButtons: true
ShowToc: true
---

# LLVM Tips/Tricks

This is a collection of tips/tricks that I have learned while working with LLVM. I will keep updating this page as I learn more.

(Last updated: 31st October 2022)

## Debugging LLVM (opt) passes with VSCode

Refer to this blog post: [Debugging LLVM (opt) passes with VSCode](/llvm_debug) to ease the process of debugging LLVM passes using VSCode's amazing debugging capabilities.

## Generating the CFG for a function

Using IDA Pro for reverse engineering binaries, has made me a huge fan of CFGs, for analyzing control flows for low level applications. Generating CFGs have been pretty helpful for me to analyze control flows especially when I use opt passes to transform the IR.

![CFG-Sample (Rendered in VSCode)](/llvm_tips/sample_CFG.png)

`opt` itself provides a way to generate CFGs for a given llvm-ir file. You can use the following command to generate the CFG for a function:

```bash
opt -disable-verify -dot-cfg --cfg-func-name=<function-name> --cfg-dot-filename-prefix=<path + prefix> <target bitcode file>
```

The bitcode file can be either a `.bc` file or a `.ll` file. The CFG will be generated in the `.dot` format. It's usually in a file named `<prefix>_<function-name>.dot`. 

If you only want the basic blocks, but not the IR instructions inside the basic blocks, you can replace the `-dot-cfg` flag with `-dot-cfg-only`.
If you want the CFG of all the functions, you can just remove the `--cfg-func-name` flag. Each function will be generated in a separate `.dot` file.

> Note: The disable-verify flag is used to disable the verification pass, which is not required for generating the CFG. This helps us to generate CFGs for invalid IRs as well, which is useful when we are trying to debug transform opt passes.

To view the dot file generated by llvm, you can use the `joaompinto.vscode-graphviz` extension for VSCode. It will render the dot file in a nice graph that you can zoom in/out and pan around.

![extension in action](/llvm_tips/graphviz_extension.png)

You need to press <kbd>Ctrl</kbd> + <kbd>Shift</kbd> + <kbd>v</kbd> to open the preview window. You can also use the command palette to open the preview window.

> Note: The `joaompinto.vscode-graphviz` extension works much better than converting the dot file into a png and then viewing it. This is because the function is too large and the png file is too large to be rendered properly. The extension renders the graph in real time, so you can zoom in/out and pan around the graph.
> It also some nice features like exporting the graph as a png, svg, etc. If you prefer to do that - without going through the hassle of using the `dot` command


## LLVM How-Tos

### Creating and Inserting call to a variable argument function in LLVM IR (using a opt pass)




## Troubleshooting LLVM issues

### Instructions get mis-recognized

This is an issue you might face if you are working with multiple versions of LLVM. You might compiling your code with one version of LLVM, but the LLVM libraries you are linking against are from a different version. This can cause the instructions to be mis-recognized. This is because the LLVM libraries are compiled with a different version of LLVM, and the instructions are not recognized properly.

This is because the LLVM instructions have an ID, and the ID is used to determine the instruction type. The IDs sometimes vary between LLVM versions which cause the instructions to be mis-recognized.

The best solution is to not do system-wide installation of LLVM, instead build LLVM from source and use the source directory as the `LLVM_DIR` when building your project. This will ensure that the LLVM libraries are built with the same version of LLVM that you are using to compile your code. 
Then use the binaries from the `build` directory to run your code.