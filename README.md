# StupidStraceParser

This is a very simple perl script that parses strace-outputs and marks errors

# How to call

Simply use 

> strace -o $LOGFILE yourprogram

> perl parse.pl --debug --filename=$LOGFILE

You can add the 

> --debug

flag for extra debug-output. Also, the

> --show\_only\_errors

parameters only shows lines that have recognized errors.

This might not recognize all commands. It stops whenever it doesn't recognize a line.

# What it's good for

Lines that it recognizes and that have errors have a red output. Also, once you opened a file-descriptor, the
program saves which file it is for and always prints the path of the descriptor. It also seperates parts of the
single lines and colors them differently. See the screenshot for this.

Also, everytime an error is detected, it tries to open the man page and look what the error means. If something
is found there, it will print the man page description of the error. (As such, it's best to run this on the
system the original program ran on, because the man pages on other systems may differ!)

At the end, it shows a summary of the most common errors.

# Screenshot of the output

![Screenshot](screenshot.png?raw=true "Screenshot")
