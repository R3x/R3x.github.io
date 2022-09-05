---
title: "Debugging LLVM (opt) passes with VSCode"
date: 2022-09-04 23:43:10  
tags: ["DEBUG", "LLVM"]
author: "Siddharth Muralee"
category: "LLVM"
params:
    ShowBreadCrumbs: true
    ShowShareButtons: true
    ShowPostNavLinks: true
    ShowCodeCopyButtons: true
ShowToc: true
---

# Debugging LLVM (opt) passes with VSCode

In this blog, I plan to look at how to debug LLVM passes (specifically opt passes) with VSCode. I have been working with opt passes in VSCode for a while, and realized that people have a really hard time debugging them. I have had labmates switch to CLion for writting LLVM passes. So, here's a guide on setting up VSCode for debugging llvm-opt passes.

## Setting up cmake-tools for VSCode

Most of the LLVM projects are built using CMake. Let's make the assumption that you are using cmake to build your project.

First, we need to install the cmake-tools extension for VSCode. The extension - [ms-vscode.cmake-tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools) - is a must-have for writing CMake projects in VSCode. It provides a lot of features, including building, debugging, and testing CMake Projects.

Now you need to create a folder for vscode settings. So from your root directory, run the following command:

```bash
mkdir .vscode
cd .vscode
code settings.json
```

Now you should have `settings.json` open, this is the file to add workspace specific configs for the extensions.
I will post some of the options that I commonly use, but you can find the full list of options [here](https://github.com/microsoft/vscode-cmake-tools/blob/0a4793e8c49c4ba9eada774080e85c69aeae5dfe/docs/cmake-settings.md#cmake-settings)


```json
{
    // Automatically configure CMake when opening a project workspace (saves you from having to run the CMake: Configure command)
    "cmake.configureOnOpen": true, 
    // If your CMakelists.txt is not in the root directory, you can specify the source directory here 
    "cmake.sourceDirectory": "${workspaceFolder}/passes/",
    // If your build directory is not in the root directory, you can specify the build directory here
    "cmake.buildDirectory": "${workspaceFolder}/passes/build",
    "cmake.clearOutputBeforeBuild": true,
    // the -j option for make (typically the number of cores on your machine)
    "cmake.parallelJobs": 15,
}
```

Now, you can open the project in VSCode and it should automatically configure the project. You can check the output of the cmake-tools extension in the `Output` tab on VScode.

### Selecting a build target 

VSCode will automatically configure the project, but it won't build it. You can build the project by running `CMake: Build` from the command palette. 

**NOTE** : You can also set a default build target by running `CMake: Select a Kit` from the command palette. This will open a list of build targets. Select the one you want to build by default.

On the bottom left corner of VSCode, you should see the build target. You can click on it to change the build target. If you have multiple passes for example, you can configure it to build all of them or just one of them. By default, it will build all the targets.

### Debugging from CMake Tools

**NOTE**: This step won't work if you are debugging opt-passes, but it might work for people trying to debug standalone executables - such as the `clang` compiler.

Normally, VSCode requires a `launch.json` to debug stuff, it's the file that tells VSCode how to launch the debugger. But, the cmake-tools extension provides a way to debug without setting this up. It doesn't work for all cases, and you can't configure the debugger as much as you can with a `launch.json`, but it's a good start.

Try running `CMake: Debug` from the command palette. If it doesn't work, keep reading to see how to set up a `launch.json`.

## Setting up a launch.json

If you are trying to debug opt passes, you will need to set up a `launch.json`. The `launch.json` is a file that tells VSCode how to launch the debugger. You can find the full list of options [here](https://code.visualstudio.com/docs/editor/debugging#_launch-configurations).

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug (GDB) : MyPass",
            "type": "cppdbg",
            "request": "launch",
            // Since we are debugging an opt pass, we need to specify the path to the opt executable
            "program": "/usr/local/bin/opt", 
            "args": [
                "-f",
                // Load the pass library, this is our target
                "-load", "${workspaceFolder}/passes/build/MyPass/libMyPass.so",
                // Arguments to the pass                    
                "-alloca-to-malloc", 
                // The input bitcode file
                "<", "test.bc", 
                // The output bitcode file
                ">", "test2.bc"
            ],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}/passes",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
        }
    ]
}
```

Now, you can run `Debug: Start Debugging` from the command palette to start debugging or use <kbd>F5</kbd>. You can also set breakpoints in the code and it should work.

## Getting arguments from prompt

Sometimes you would want to keep changing parts of the input to the pass. For example, you might want to change the input bitcode file. You can do this by using the `args` option in the `launch.json`. But, this is not very convenient. You can do this by defining a input prompt for the file.

Make the following changes to the `launch.json` :

```json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug (GDB) : MyPass",
            "type": "cppdbg",
            "request": "launch",
            "program": "/usr/local/bin/opt", 
            "args": [
                "-f",
                "-load", "${workspaceFolder}/passes/build/MyPass/libMyPass.so",
                "-alloca-to-malloc", 
                "<", "${input:inputBitcode}", 
                ">", "test2.bc"
            ],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}/passes",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
        }
    ],
    "inputs": [
        {
            "id": "inputBitcode",
            "type": "promptString",
            "description": "Input bitcode file",
            "default": "${workspaceFolder}/passes/test.bc"
        }
    ]
}
```

Now, when you run `Debug: Start Debugging` from the command palette, you will be prompted to enter the input bitcode file. You can also change the default value in the `launch.json` to change the default value.

The same technique can be used to get flags and other command line arguments for the passes. 

You can also use the `pickString` option to select from a list of options. For example, you can use this to select the pass to debug.

```json
{
    "id": "passToDebug",
    "type": "pickString",
    "description": "Pass to debug",
    "options": [
        "MyPass",
        "MyOtherPass"
    ]
}
```

This means that you can replace your `args` with the following to select the pass to debug:

```json
"-load",
"${workspaceFolder}/passes/build/${input:passToDebug}/${input:passToDebug}.so",
```

## Conclusion

Well, that's it. I hope this helps you debug your LLVM passes. If you have any questions, feel free to reach out to me. I will try to answer them as soon as I can.
