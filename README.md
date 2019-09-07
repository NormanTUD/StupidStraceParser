# StupidStraceParser
This is a very simple perl script that parses strace-outputs and marks errors

# How to call

Simply use 

> strace -o $LOGFILE yourprogram

perl parse.pl --debug --filename=$LOGFILE

This might not recognize all commands. It stops whenever it doesn't recognize a line.
