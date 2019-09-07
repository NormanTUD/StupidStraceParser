#!/usr/bin/perl

sub debug (@);
sub printmsg (@);

use strict;
use warnings FATAL => "all";
use autodie;
use Hash::Util;
use Data::Dumper;
use Term::ANSIColor;

my %errors = ();

my %options = (
	filename => undef,
	debug => 1
);

analyze_args(@ARGV);

	
my %open_fds = (
	0 => 'STDIN',
	1 => 'STDOUT',
	2 => 'STDERR'
);

main();

sub main {
	return unless $options{filename};
	


	#my %stats = ();
	open my $fh, '<', $options{filename};

	my $hex = qr/0x[a-f0-9]+/;
	my $num = qr/-?\d+/;
	my $hex_or_num = qr/(?:$hex|$num)/;
	my $null_or_num = qr/(?:NULL|$hex_or_num)/;
	my $mode = qr/(?:[A-Z_|<x]+(?:\d+)?)(?:\s*or\s*(?:[A-Z_|<x]+(?:\d+)?))*/;
	my $hex_or_num_or_null = qr/(?:$hex_or_num|NULL)/;
	my $hex_or_num_or_null_or_mode = qr/(?:$hex_or_num|NULL|$mode)/;
	my $ret = qr/(?<ret>$hex_or_num_or_null_or_mode|\?)/;

	my $i = 0;

	while (my $line = <$fh>) {
		$line =~ s#^\d*\s*##g;
		$i++;
		next if $line =~ m#<unfinished \.\.\.>#;
		next if $line =~ m#<\.\.\. .* resumed>#;
		if(check_balanced_objects($line) ne "OK") {
			warn "ERROR: In line >>>\n$line<<< there are unbalanced characters! Skipping this line.\n";
			next;
		}
#exit if $line =~ m#nanosleep#;
#use re 'debugcolor';
		if($line =~ m#^open\("(?<filename>.*?)"(?:,\s*(?<rest>.*))?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))?#g) {
			printmsg "Opening $+{filename} in mode $+{rest}, returned fd $+{ret}".error($+{error});
			if(!error($+{error})) {
				$open_fds{$+{ret}} = $+{filename};
			}
		} elsif ($line =~ m#^poll\(\[\{fd=(?<fd>\d+),.*\)\s*=\s(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#poll([{fd=5, events=POLLIN}, {fd=20, events=POLLIN}], 2, 0) = 0 (Timeout)
			printmsg "Polling for $+{fd} [ -> ".fd_to_filename($+{fd})."], returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^execve\("(?<programpath>[^"]+)"#) {
			printmsg "execve'ing $+{programpath}";
			#$stats{execve}{$+{programpath}}++;
		} elsif ($line =~ m#^brk\((?<mem>$hex_or_num_or_null)\)\s*=\s*(?<ret>$hex_or_num_or_null)#) {
			printmsg "brk($+{mem}) = $+{ret}";
		} elsif ($line =~ m#^access\("(?<filename>.*?)",\s*(?<mode>[A-Z_]+)\)\s*=\s*(?<return>$num)\s*(?<error>.*)#) {
			#access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
			#$stats{access}{$+{filename}}{$+{mode}}{$+{return}}{$+{error}}++;
			if(exists $+{error} && $+{error}) {
				printmsg "Accessing $+{filename} in mode $+{mode}, returned $+{return}".error($+{error});
			} else {
				printmsg "Accessing $+{filename} in mode $+{mode}, returned $+{return}";
			}
		} elsif ($line =~ m#^fstat\((?<fd>\d+),(?<rest>.*)?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#fstat(3, {st_mode=S_IFREG|0644, st_size=344055, ...}) = 0
			#$stats{fstat}{$+{fd}}++;
			printmsg "fstat'ting $+{fd} (to ".fd_to_filename($+{fd}).") [$+{rest}] returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^mmap\((?<addr>$null_or_num),\s*(?<length>$null_or_num)(?<rest>.*)?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x2ab6b925f000
			#mmap(NULL, 344055, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fab7dfa9000
			#mmap(0x2b4e98d99000, 24576, PROT_READ|PROT_WRITE, MAP_PRIV{st_mode=S_IFREG|0775, st_size=3693248, ) = 0x2b4e772   mma771   close(4)                          = 0
			#mmap(NULL, 262144, PROT_READ|PROT_WRITE, MAP_PRIVATE) = 4
			#mmap(0x2b4a2c676000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 4, 0) = 4
			printmsg "mmap($+{addr}, $+{length}, $+{rest}) = $+{ret}".error($+{error});
		} elsif ($line =~ m#^mmap\((?<addr>$hex_or_num_or_null_or_mode),\s*.*?\)\s*=\s*(?<mem>$hex_or_num_or_null_or_mode)(?:\s*(?<error>.*))#) {
			#mmap(0x2b4a2c676000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 4, 0) = 4
			printmsg "mmap'ing $+{addr}, ..., returned = $ret".error($+{error});
		} elsif ($line =~ m#^mprotect\((?<mem>$hex),\s(?<len>$num),\s*(?<mode>$mode)\)\s*=\s*(?<ret>$num)#) {
			#mprotect(0x7fab7dbd8000, 2097152, PROT_NONE) = 0
			printmsg "Protecting memory at $+{mem} to $+{len} in mode $+{mode}, returned $+{ret}";
		} elsif ($line =~ m#^close\((?<fd>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#close(3)
			printmsg "Closing $+{fd} (to ".fd_to_filename($+{fd})."), returned $+{ret}".error($+{error});
			my $fd = $+{fd};
			if($fd !~ m#^(?:0|1|2)$#) {
				delete $open_fds{$fd};
			}
		} elsif ($line =~ m#^read\((?<fd>\d+),\s*(?:(?:".*?"(?:\.\.\.)?)|$hex)(?:,\s+(?<len>\d+))?\)\s*=\s*(?<readchars>$ret)(?:\s*(?<error>.*))#) {
			#read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\30\0\0\0\0\0\0"..., 832) = 832
			#read(10, 0x7ffd3f49825f, 1)             = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
			if(exists $+{len} && defined $+{len}) {
				if(exists $+{error} && $+{error}) {
					printmsg "Reading $+{len} from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}".error($+{error});
				} else {
					printmsg "Reading $+{len} from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}"; 
				} 
			} else {
				if(exists $+{error} && $+{error}) {
					printmsg "Reading from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}".error($+{error});
				} else {
					printmsg "Reading from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}"; 
				} 
			}
		} elsif ($line =~ m#^arch_prctl\((?<mode>$mode),\s*(?<mem>$hex_or_num_or_null)\)\s*=\s*(?<ret>$num)#) {
			#arch_prctl(ARCH_SET_FS, 0x7fab7dfa5f80) = 0
			printmsg "arch_prctl($+{mode}, $+{mem}) = $+{ret}";
		} elsif ($line =~ m#^munmap\((?<mem>$hex_or_num_or_null),\s*(?<size>$num)\)\s*=\s*(?<ret>$hex_or_num_or_null_or_mode)(?:\s*(?<error>.*))#) {
			#munmap(0x7fab7dfa9000, 344055)          = 0
			#munmap(0x2b4a2fc05000, 262144) 10857 s10859 mmap(NULL, 262144, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x2b4a2fc05000
			#
			printmsg "munmap($+{mem}, $+{size}) = $+{ret}".error($+{error});
		} elsif ($line =~ m#^getuid\(\)\s*=\s*(?<uid>\d+)#) {
			printmsg "getuid() = $+{uid}";
		} elsif ($line =~ m#^geteuid\(\)\s*=\s*(?<uid>\d+)#) {
			printmsg "geteuid() = $+{uid}";
		} elsif ($line =~ m#^getgid\(\)\s*=\s*(?<gid>\d+)#) {
			printmsg "getgid() = $+{gid}";
		} elsif ($line =~ m#^getegid\(\)\s*=\s*(?<gid>\d+)#) {
			printmsg "getegid() = $+{gid}";
		} elsif ($line =~ m#^getrlimit\((?<mode>$mode),\s*[^\)]+\)\s*=\s*(?<ret>$num)#) {
			#getrlimit(RLIMIT_NOFILE, {rlim_cur=1024, rlim_max=4*1024}) = 0
			printmsg "getrlimit($+{mode}, ...) = $+{ret}";
		} elsif ($line =~ m#^ioctl\((?<fd>$num),\s*(?<mode>$mode)(?:,\s*.*?)?\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
			#ioctl(10, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig -icanon -echo ...}) = 0
			#ioctl(2, TCGETS, 0x7ffd3f481be0)        = -1 ENOTTY (Inappropriate ioctl for device)
			if(exists $+{error} && $+{error}) {
				printmsg "ioctl($+{fd} [ -> ".fd_to_filename($+{fd})."], ...) = $+{ret}".error($+{error});
			} else {
				printmsg "ioctl($+{fd} [ -> ".fd_to_filename($+{fd})."], ...) = $+{ret}";
			}
		} elsif ($line =~ m#^readlink\("(?<link>[^"]+)",\s*(?<to>(?:(?:".*?"+(?:\.\.\.)?)|$hex)),\s*(?<len>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#readlink("/proc/self/fd/0", "/dev/pts/2", 4095) = 10
			#readlink("/usr/bin/python3.5", 0x7fffdf0f3b50, 4096) = -1 EINVAL (Invalid argument)
			#readlink("/proc/self/exe", "/software/taurus/libraries/pytho"..., 4096) = 65
			printmsg "Reading symbolic link $+{link} (to $+{to}), length: $+{len}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^stat\("(?<file>[^"]+)"(?:,\s*.+)?\)\s*=\s*(?<ret>\d*)#) {
			#stat("/dev/pts/2", {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 2), ...}) = 0
			printmsg "stat'ting $+{file}, returned $+{ret}";
		} elsif ($line =~ m#^lstat\("(?<file>.+?)",\s*.+\)\s*=\s*(?<ret>\d*)#) {
			#lstat("/home/norman/.oh-my-zsh/custom/plugins/zsh-autosuggestions", {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
			#lstat("\"^opn", 0x55d2799deac0)         = -1 ENOENT (No such file or directory)
			printmsg "lstat'ting $+{file}, returned $+{ret}";
		} elsif ($line =~ m#^fcntl\((?<fd>\d+),\s*(?<mode>$hex_or_num_or_null_or_mode)(?:,\s*(?<param>$hex_or_num_or_null_or_mode))?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#fcntl(3, F_DUPFD, 10)                   = 10
			if(exists $+{error} && $+{error}) {
				printmsg "manipulating fd with fcntl $+{fd} (-> ".fd_to_filename($+{fd})."), mode: $+{mode}, returned $+{ret}".error($+{error});
			} else {
				printmsg "manipulating fd with fcntl $+{fd} (-> ".fd_to_filename($+{fd})."), mode: $+{mode}, returned $+{ret}";
			}
		} elsif ($line =~ m#^getpid\(\)\s*=\s*(?<pid>\d*)#) {
			#getpid()                                = 9987
			printmsg "getpid() = $+{pid}";
		} elsif ($line =~ m#^getppid\(\)\s*=\s*(?<ppid>\d*)#) {
			#getppid()                               = 9985
			printmsg "getppid() = $+{ppid}";
		} elsif ($line =~ m#^getpgrp\(\)\s*=\s*(?<ret>\d+)#) {
			#getpgrp()                               = 9985
			printmsg "process's PGID: $+{ret}";
		} elsif ($line =~ m#^setpgid\((?<pid>\d+),\s*(?<pgid>\d+)\)\s*=\s*(?<ret>\d+)#) {
			#setpgid(0, 0)                           = 0
			printmsg "setpgid($+{pid}, $+{pgid}) = $+{ret}";
		} elsif ($line =~ m#^rt_sigprocmask\((?<mode>$mode),\s*.+,\s*(?<num>\d+)\)\s*=\s*(?<ret>\d+)#) {
			#rt_sigprocmask(SIG_BLOCK, [TSTP TTIN TTOU], [], 8) = 0
			printmsg "Setting signal $+{mode} (signal $+{num}), returned $+{ret}";
		} elsif ($line =~ m#^pipe\(\[(?<pipe1>\d*),\s*(?<pipe2>\d+)]\)\s*=\s*(?<ret>\d+)(?:\s*(?<error>.*))#) {
			#pipe([3, 4])                            = 0
			printmsg "Opening pipe $+{pipe1}, set to $+{pipe2}".error($+{error});
			$open_fds{$+{pipe1}} = $+{pipe2};
		} elsif ($line =~ m#^pipe2\(\[(?<pipe1>\d*),\s*(?<pipe2>\d+)],\s*(?<mode>$mode)\)\s*=\s*(?<ret>\d+)(?:\s*(?<error>.*))#) {
			#pipe2([3, 4], O_CLOEXEC)                = 0
			printmsg "Opening pipe2 $+{pipe1}, set to $+{pipe2} with mode $+{mode}".error($+{error});
			$open_fds{$+{pipe1}} = $+{pipe2};
			#die Dumper \%open_fds;
		} elsif ($line =~ m#^dup\((?<fd>\d+)\)\s*=\s*(?<newfd>\d+)#) {
			#dup(0)                                  = 5
			printmsg "Duplicating fd $+{fd} (-> $open_fds{$+{fd}}) to new fd $+{newfd}";
			$open_fds{$+{newfd}} = $open_fds{$+{fd}};
		} elsif ($line =~ m#^dup2\((?<oldfd>\d+),\s*(?<newfd>\d*)\)\s*=\s*(?<ret>\d+)#) {
			#dup2(3, 1)                              = 1
			if(exists $open_fds{$+{oldfd}}) {
				printmsg "Duplicating fd $+{oldfd} (-> $open_fds{$+{oldfd}}) to newfd $+{newfd}, returned $+{ret}";
				$open_fds{$+{newfd}} = $open_fds{$+{oldfd}};
			} else {
				printmsg "Duplicating fd $+{oldfd} (-> !!! unknown_fd !!!) to newfd $+{newfd}, returned $+{ret}";
			}
		} elsif ($line =~ m#^gettimeofday\([^\)]+\)\s*=\s*(\d+)#) {
			#gettimeofday({tv_sec=1567854290, tv_usec=264153}, {tz_minuteswest=-120, tz_dsttime=0}) = 0
			printmsg "gettimeofday(...)";
		} elsif ($line =~ m#^socket\((?<domain>$mode),\s*(?<type>$mode),\s*(?<protocol>$mode)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 11
			#socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
			#socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES (Permission denied)
			printmsg "Opening socket $+{domain} with type $+{type} and protocol $+{protocol}, returned $+{ret}".error($+{error});
			$open_fds{$+{ret}} = $+{domain};
		} elsif ($line =~ m#^connect\((?<socketfd>\d+),\s*.*?\)\s*=\s*(?<ret>$ret)\s*((?<error>.*))?#) {
			#connect(11, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
			#connect(4, {sa_family=AF_INET, sin_port=htons(30290), sin_addr=inet_addr("172.24.138.246")}, 16) = -1 EINPROGRESS (Operation now in progress)
			printmsg "Connecting to $+{socketfd} (-> ".fd_to_filename($+{socketfd})."), returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^lseek\((?<fd>\d+),\s*(?<offset>$num),\s*(?<mode>$mode)\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#lseek(3, 0, SEEK_CUR)                   = 0
			#lseek(11, 0, SEEK_CUR)                  = 0
			printmsg "lseek'ing $+{fd} (-> ".fd_to_filename($+{fd})."), mode = $+{mode}, returned: $+{ret}".error($+{error});
		} elsif ($line =~ m#^select\((?<fd>\d+),.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#select(0, NULL, NULL, NULL, {0, 500000}) = 0 (Timeout)
			printmsg "Selecting $+{fd}, returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^madvise\((?<addr>$hex_or_num_or_null),.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#madvise(0x2abca506a000, 2076672, MADV_DONTNEED) = 0
			printmsg "Memory advisor for $+{addr} returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^uname\(#) {
			#uname({sysname="Linux", nodename="alanwatts", ...}) = 0
			printmsg "uname called";
		} elsif ($line =~ m#^newfstatat\((?<fd>\d+),\s*"(?<path>.*?)",.*?\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#newfstatat(13, "sys/bus/pci/devices/0000:07:00.1//mic", 0x7ffd54c66a30, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
			printmsg "newfstatat called for fd $+{fd} [ -> ".fd_to_filename($+{fd})."]. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^statfs\("(?<path>.*?)",.*?\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#statfs("/dev/hugepages", {f_type=HUGETLBFS_MAGIC, f_bsize=2097152, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={0, 0}, f_namelen=255, f_frsize=2097152, f_flags=ST_VALID|ST_RELATIME}) = 0
			printmsg "Called statfs($+{path}, ...). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^sched_get_priority_max\((?<mode>$mode)\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#sched_get_priority_max(SCHED_RR)  = 99
			printmsg "Called sched_get_priority_max($+{mode}). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^sched_get_priority_min\((?<mode>$mode)\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#sched_get_priority_min(SCHED_RR)  = 1
			printmsg "Called sched_get_priority_min($+{mode}). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^mmastat\("(?<filename>.*?)",\s*.*\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#mmastat("/home/h8/s3811141/nnopt/script/hyperopt-mongo-worker", {st_mode=S_IFREG|0755, st_size=175, ...}) = 0
			printmsg "mmstat called for $+{filename}, returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^clock_gettime\(#) {
			#clock_gettime(CLOCK_REALTIME, {tv_sec=1567868779, tv_nsec=484741873}) = 0
			printmsg "got time via clock_gettime()";
		} elsif ($line =~ m#^sigaltstack\(.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#sigaltstack({ss_sp=0x559744542e10, ss_flags=0, ss_size=8192}, NULL) = 0
			printmsg "called sigaltstack, returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^getcwd\("(?<pwd>.*?)",\s*(?<len>\d*)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#getcwd("/home/norman/test/zshstrae", 4096) = 27
			printmsg "getcwd $+{pwd}, length $+{len}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^statfs\("(?<fs>.*?)",\s*(?<buf>$hex)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#statfs("/selinux", 0x7fffdf103df0)      = -1 ENOENT (No such file or directory)
			printmsg "Getting file system statistics for $+{fs} (buf: $+{buf}). Returned: $+{ret}".error($+{error});
		} elsif ($line =~ m#^sched_getaffinity\((?<pid>$num),\s*(?<cpusetsize>$num),\s*(?<mask>.*?)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#sched_getaffinity(0, 128, [0, 1])       = 64
			printmsg "Set/get CPU thread affinity mask called for $+{pid}. CPUsetsize = $+{cpusetsize}. Mask = $+{mask}. Returned: $+{ret}".error($+{error});
		} elsif ($line =~ m#^sysinfo\(#) {
			#sysinfo({uptime=172588, loads=[119840, 92256, 95200], totalram=8264978432, freeram=1597956096, sharedram=171421696, bufferram=836091904, totalswap=4060082176, freeswap=3983908864, procs=764, totalhigh=0, freehigh=0, mem_unit=1}) = 0
			printmsg "sysinfo called";
		} elsif ($line =~ m#^getrusage\((?<who>$mode),\s*[^\)]+\)\s*=\s*(?<ret>$num)#) {
			#getrusage(RUSAGE_CHILDREN, {ru_utime={tv_sec=0, tv_usec=0}, ru_stime={tv_sec=0, tv_usec=0}, ...}) = 0
			printmsg "Getting ressource usage of $+{who}, returned $+{ret}";
		} elsif ($line =~ m#^rt_sigaction\((?<signal>$mode),\s*.+?\)\s*=\s*(?<ret>$num)(\s*(?<error>.*))?#) {
			#rt_sigaction(SIGHUP, {sa_handler=SIG_DFL, sa_mask=[HUP], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7fab7d136060}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
			if(exists $+{error} && $+{error}) {
				printmsg "Reading/changing $+{signal}, returned $+{ret}".error($+{error});
			} else {
				printmsg "Reading/changing $+{signal}, returned $+{ret}";
			}
		} elsif ($line =~ m#^getdents\((?<fd>\d+),.*?\)\s*=\s*(?<ret>\d*)#) {
			#getdents(3, /* 276 entries */, 32768)   = 10096
			printmsg "Get directory entries for fd $+{fd} (-> ".fd_to_filename($+{fd})."), returned $+{ret}";
		} elsif ($line =~ m#^getdents64\((?<fd>\d+),.*?\)\s*=\s*(?<ret>\d*)#) {
			#getdents64(4, /* 9 entries */, 280) = 216
			printmsg "Get directory entries (getdents64) for fd $+{fd} (-> ".fd_to_filename($+{fd})."), returned $+{ret}";
		} elsif ($line =~ m#^clone\((?<params>.*?)\)\s*=\s*(?<ret>$num)#) {
			#clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fab7dfa6250) = 9988
			printmsg "Called clone($+{params}), returned $+{ret}";
		} elsif ($line =~ m#^rt_sigsuspend\(\[(?<mode>$mode?)\],\s*(?<sig>\d+)\)\s*=\s*$ret(?:\s*(<error>.*))?#) {
			#rt_sigsuspend([INT], 8)                 = ? ERESTARTNOHAND (To be restarted if no handler)
			#rt_sigsuspend([], 8)                    = ? ERESTARTNOHAND (To be restarted if no handler)
			if(exists $+{error} && $+{error}) {
				printmsg "Waiting for signal $+{sig} with $+{mode}, returned $+{ret}".error($+{error});
			} else {
				printmsg "Waiting for signal $+{sig} with $+{mode}, returned $+{ret}";
			}
		} elsif ($line =~ m#^set_tid_address\((?<mem>$hex)\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#set_tid_address(0x7f59309531d0)         = 31114
			printmsg "Set pointer to thread id $+{mem} returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^set_robust_list\((?<mem>$hex),\s*(?<size>\d+)\)\s*=\s*(?<ret>\d*)(?:\s*(?<error>.*))#) {
			#set_robust_list(0x7f59309531e0, 24)     = 0
			printmsg "get_robust_list($+{mem}) = $+{ret}".error($+{error});
		} elsif ($line =~ m#^exit_group\((?<exit>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#exit_group(0)                           = ?
			printmsg "Exiting with $+{exit} returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^exit\((?<exit>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#exit(0)                           = ?
			printmsg "Exiting with $+{exit} returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^(\+\+\+|---)(.*)#) {
			#+++ exited with 0 +++
			#--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=9988, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
			printmsg "Got weird line $2";
		} elsif ($line =~ m#^wait4\((?<pid>$num),\s*(?<params>.*?)\)\s*=\s*(?<ret>)(?:\s*(?<error>.*))#) {
			#wait4(-1, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WNOHANG|WSTOPPED|WCONTINUED, {ru_utime={tv_sec=0, tv_usec=4000}, ru_stime={tv_sec=0, tv_usec=0}, ...}) = 9988
			if(exists $+{error} && $+{error}) {
				printmsg "Waiting for process $+{pid} to change with parameters $+{params}, returning $+{ret}. Error $+{error}";
			} else {
				printmsg "Waiting for process $+{pid} to change with parameters $+{params}, returning $+{ret}";
			}
		} elsif ($line =~ m#^rt_sigreturn\((?<params>.*?)\)\s*=\s*$ret(?:\s*(?<error>.*))#) {
			#rt_sigreturn({mask=[CHLD WINCH]})       = -1 EINTR (Interrupted system call)
			if(exists $+{error} && $+{error}) {
				printmsg "Return from sighandler, returned $+{ret}".error($+{error});
			} else {
				printmsg "Return from sighandler, returned $+{ret}.";
			}
		} elsif ($line =~ m#^kill\((?<pid>$num),\s*(?<signal>$mode)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#kill(9998, SIG_0)                       = 0
			#kill(-10018, SIG_0)                     = -1 ESRCH (No such process)
			if(exists $+{error} && $+{error}) {
				printmsg "Sending $+signal to $+pid. Returned $+{ret}".error($+{error});
			} else {
				printmsg "Sending $+signal to $+pid. Returned $+{ret}";
			}
		} elsif ($line =~ m#^write\((?<fd>\d+),\s*(?<rest>.*?)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#write(1, "ack-grep not found\n", 19)    = 19
			#write(2, "INFO:hyperopt.mongoexp:PROTOCOL "..., 38) = -1 EPIPE (Broken pipe)
			my ($rest, $tfd, $tret, $terror) = ($+{rest}, $+{fd}, $+{ret}, $+{error});
			printmsg "Writing $+{rest} to fd $+{fd} ( -> ".fd_to_filename($+{fd})."), returned $+{ret}".error($+{error});
			#if($line =~ m#INFO:hyperopt.mongoexp:PROTOCOL# && $line =~ m#-1#) {
			#	warn $line;
			#	die Dumper \%copy;
			#}
		} elsif ($line =~ m#^symlink\("(?<target>[^"]*)", "(?<linkpath>[^"]*)"\)\s*=\s*(?<ret>$ret)#) {
			#symlink("/pid-9987/host-alanwatts", "/home/norman/.zsh_history.LOCK") = 0
			printmsg "Creating symbolic link $+{target} to $+{linkpath}";
		} elsif ($line =~ m#^unlink\("(?<filename>[^"]+)"\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#unlink("/home/norman/.zsh_history.LOCK") = 0
			if(exists $+{error} && $+{error}) {
				printmsg "Unlinking file $+filename, returned $+{ret}".error($+{error});
			} else {
				printmsg "Unlinking file $+filename, returned $+{ret}";
			}
		} elsif ($line =~ m#^capget\(#) {
			#capget({version=_LINUX_CAPABILITY_VERSION_3, pid=0}, NULL) = 0
			printmsg "Called capget";
		} elsif ($line =~ m#^capset\(#) {
			#capset({_LINUX_CAPABILITY_VERSION_3, 0}, {0, 0, 0}) = 0
			printmsg "Called capset";
		} elsif ($line =~ m#^setuid\(.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#setuid(2105408)                   = 0
			printmsg "Setting effective user id. Return $+{ret}".error($+{error});
		} elsif ($line =~ m#^prctl\((?<mode>$mode),\s*(?<number>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#prctl(PR_SET_KEEPCAPS, 1)         = 0
			printmsg "Called prctl($+{mode}, $+{number}). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^setsockopt\((?<socket>\d+),\s.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#setsockopt(4, SOL_TCP, TCP_NODELAY, [1], 4) = 0
			printmsg "Setting socket option for socket $+{socket}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^getsockopt\((?<socket>\d+),\s.*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#getsockopt(4, SOL_TCP, TCP_KEEPIDLE, [7200], [4]) = 0
			printmsg "Getting socket option for socket $+{socket}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^sendto\((?<socket>\d+),.*\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#sendto(4, "_\0\0\0{\337\2001\0\0\0\0\335\7\0\0\0\0\0\0\0J\0\0\0\20ismast"..., 95, 0, NULL, 0) = 95
			printmsg "Send to $+{socket}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^recvfrom\((?<socket>\d+),.*\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#recvfrom(4, "\340\0\0\0\313\234\0\0{\337\2001\335\7\0\0", 16, 0, NULL, NULL) = 16
			printmsg "Receive from $+{socket} ( -> ".fd_to_filename($+{socket})."). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^alarm\((?<time>\d+)\)\s*=\s*(?<ret>$num)#) {
			#alarm(0)                                = 0
			printmsg "Called alarm($+{time}), returned $+{ret}";
		} elsif ($line =~ m#^socket\((?<socket>$mode)(?<rest>.*)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#socket(AF_LOCAL, SOCK_STREAM, 0)  = 22
			printmsg "Opened socket $+{socket}$+{rest}. Returned $+{ret}".error($+{error});
			if(!(exists $+{error} && $+{error})) {
				$open_fds{$+{ret}} = $+{socket};
			}
		} elsif ($line =~ m#^nanosleep\(#) {
			#nanosleep({tv_sec=0, tv_nsec=1000000}, 0x7fffdf101840) = 0
			printmsg "nanosleep'ing";
		} elsif ($line =~ m#^futex\((?<mem>$hex),\s*(?<mode>$mode),\s*(?<val>$num)(?:.*)?\)\s*=\s*(?<ret>$ret)#) {
			#futex(0x7f23589948a8, FUTEX_WAKE_PRIVATE, 2147483647) = 0
			#futex(0x7f2357b1fa3c, FUTEX_WAKE_OP_PRIVATE, 1, 1, 0x7f2357b1fa38, FUTEX_OP_SET<<28|0<<12|FUTEX_OP_CMP_GT<<24|0x1) = 1
			printmsg "fast user space locking, mem: $+{mem}, mode: $+{mode}, val: $+{val}. Returned $+{ret}";
		} elsif ($line =~ m#^getrandom\(".*?"(?:\.\.\.)?,\s*(?<len>$num),\s*(?<flags>$mode)\)\s*=\s*(?<ret>$ret)#) {
			#getrandom("\262\341v\6(\32\35\375\300I\4+\351{\215V\265:\344\364\360\345N\364", 24, GRND_NONBLOCK) = 24
			#getrandom("\201\205\254\20:I\267'\357\330(\243\322\345\306P6\224g\1Q\257V\364\217\">\rP\233>\351"..., 2500, GRND_NONBLOCK) = 2500
			printmsg "get_random with length $+{len} and flags $+{flags} returned $+{ret}";
		} elsif ($line =~ m#^bind\((?<socket>\d+), .*?\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#bind(3, {sa_family=AF_INET6, sin6_port=htons(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, 28) = -1 EADDRNOTAVAIL (Cannot assign requested address)
			printmsg "bind'ing $+{socket}, returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^chdir\("(?<folder>.*?)"\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#chdir("/home/h8/s3811141/nnopt/projects/bm_logfile") = 0
			printmsg "Changing dir to $+{folder}. Returned $ret".error($+{error});
		} elsif ($line =~ m#^openat\((?<dirfd>$hex_or_num_or_null_or_mode),\s*"(?<path>.*?)",\s*(?<mode>.*?)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#openat(AT_FDCWD, "/home/h8/s3811141/nnopt/script/", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 3
			printmsg "Trying to open $+{path} with dirfd = $+{dirfd} and mode = $+{mode}. Returned $+{ret}".error($+{error});
			$open_fds{$+{ret}} = $+{path};
		} elsif($line =~ m#^(?<funcname>[a-z0-9_]+)\((?<firstparam>.*?)\)\s*=\s*(?<return>$ret)(?:\s*(?<error>.*))?#g) {
			#get_mempolicy(NULL, NULL, 0, NULL, 0) = 0
			printmsg "Called $+{funcname}($+{firstparam}). Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^\s*$#) {
		} else {
			chomp $line;
			die "Unknown line $i\n".color("red").$line.color("reset")."\n";
		}
		warn $i if $i % 10000 == 0;
	}
	close $fh;
}

sub analyze_args {
	my @args = @_;

	for (@_) {
		if(m#^--debug$#) {
			$options{debug} = 1;
		} elsif (m#--filename=(.*)#) {
			if(-e $1) {
				$options{filename} = $1;
			} else {
				die "$1 not found!";
			}
		} else {
			die "Unknown parameter $_";
		}
	}
}

sub debug (@) {
	if($options{debug}) {
		foreach (@_) {
			warn color("blue")."$_".color("reset")."\n";
		}
	}
}

sub printmsg (@) {
	my $msg = shift;
	print color("blue").$msg.color("reset")."\n";
}	

sub fd_to_filename {
	my $fd = shift;

	if(exists $open_fds{$fd}) {
		return color("underline").$open_fds{$fd}.color("reset").color("blue");
	} else {
		return color("red")."!!! ERROR: unknown_fd !!!".color("blue");
	}
}

sub error {
	my $error = shift;
	chomp $error;

	if($error) {
		$errors{$error}++;
		return ". ".color("underline red")."ERROR: $error".color("reset").color("blue")." ";
	} else {
		return '';
	}
}

sub check_balanced_objects {
	my $string = shift;


	$string =~ s#\\\\##g;
	my $number_of_quotes = () = $string =~ /(?<!\\)"/gi;

	if($number_of_quotes % 2 == 0) {
		$string =~ s#".*?"#""#g;
		my $number_of_open_brackets = () = $string =~ /(?<!\\)\(/gi;
		my $number_of_close_brackets = () = $string =~ /(?<!\\)\)/gi;
		if($number_of_open_brackets == $number_of_close_brackets) {
			return "OK";
		}
	}
	return "NOT OK";
}

END {
	if (keys %errors) {
		print "Most common errors:\n";
		foreach my $error (sort { $errors{$a} <=> $errors{$b} } keys %errors) {
			print "\t$error: $errors{$error}\n";
		}
	}
}
