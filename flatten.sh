#!/bin/bash

# Get all subdirectories of the directory wiki
for dir in wiki/*; do
    # move all files in subdirectories to the directory content/posts
    # rename each file with the name of the subdirectory-file

    # get the name of the subdirectory
    dir_name=$(basename "$dir")
    # get all files in the subdirectory
    for file in "$dir"/*; do
        # get the name of the file
        file_name=$(basename "$file")
        # move the file to the directory content/posts
        echo "Moving $file to content/posts/$dir_name-$file_name"
        cp "$file" "content/posts/$dir_name-$file_name"
    done
done