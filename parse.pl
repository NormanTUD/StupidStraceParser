#!/usr/bin/perl

sub debug (@);
sub printmsg (@);

use strict;
use warnings FATAL => "all";
use autodie;
use Hash::Util;
use Data::Dumper;
use Term::ANSIColor;

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
	


	my %pipe_fds = ();

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
#use re 'debugcolor';
		if($line =~ m#^open\("(?<filename>[^"]+)",\s*(?<mode>[A-Z_|]+)(?:,\s*(?<mode2>$num))?\)\s*=\s*(?<return>$num)(?:\s*(?<error>))?#g) {
			if($+{mode2}) {
				if(exists $+{error} && $+{error}) {
					printmsg "Opening $+{filename} in mode $+{mode} + $+{mode2}, returned fd $+{return}".error($+{error});
				} else {
					printmsg "Opening $+{filename} in mode $+{mode} + $+{mode2}, returned fd $+{return}";
					$open_fds{$+{return}} = $+{filename};
				}
			} else {
				if(exists $+{error} && $+{error}) {
					printmsg "Opening $+{filename} in mode $+{mode}, returned fd $+{return}".error($+{error});
				} else {
					printmsg "Opening $+{filename} in mode $+{mode}, returned fd $+{return}";
					$open_fds{$+{return}} = $+{filename};
				}
			}
		} elsif ($line =~ m#^execve\("(?<programpath>[^"]+)"#) {
			printmsg "execve'ing $+{programpath}";
			#$stats{execve}{$+{programpath}}++;
		} elsif ($line =~ m#^brk\((?<mem>$hex_or_num_or_null)\)\s*=\s*(?<ret>$hex_or_num_or_null)#) {
			printmsg "brk($+{mem}) = $+{ret}";
		} elsif ($line =~ m#^access\("(?<filename>.*?)",\s*(?<mode>[A-Z_]+)\)\s*=\s*(?<return>$num)\s*(?<error>.*)#) {
			#access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
			#$stats{access}{$+{filename}}{$+{mode}}{$+{return}}{$+{error}}++;
			if(exists $+{error} && $+{error}) {
				printmsg "Accessing $+{filename} in mode $+{mode}, returned $+{return} with error $+{error}";
			} else {
				printmsg "Accessing $+{filename} in mode $+{mode}, returned $+{return}";
			}
		} elsif ($line =~ m#^fstat\((?<fd>\d+), #) {
			#fstat(3, {st_mode=S_IFREG|0644, st_size=344055, ...}) = 0
			#$stats{fstat}{$+{fd}}++;
			printmsg "fstatting $+{fd} (to ".fd_to_filename($+{fd}).")";
		} elsif ($line =~ m#^mmap\((?<addr>$null_or_num),\s*(?<length>$null_or_num),\s*(?<prot>$mode),\s*(?<flags>$mode),\s*(?<fd>$num),\s*(?<offset>$hex_or_num)\)\s*=\s*(?<mem>$hex)#) {
			#printmsg "mmap($+{addr}, $+{length}, $+{prot}, $+{flags}, $+{num}, $+{offset} = $+{mem}";
			#mmap(NULL, 344055, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fab7dfa9000
		} elsif ($line =~ m#^mprotect\((?<mem>$hex),\s(?<len>$num),\s*(?<mode>$mode)\)\s*=\s*(?<ret>$num)#) {
			#mprotect(0x7fab7dbd8000, 2097152, PROT_NONE) = 0
			printmsg "Protecting memory at $+{mem} to $+{len} in mode $+{mode}, returned $+{ret}";
		} elsif ($line =~ m#^close\((?<fd>\d+)\)#) {
			#close(3)
			printmsg "Closing $+{fd} (to ".fd_to_filename($+{fd}).")";
			my $fd = $+{fd};
			if($fd !~ m#^(?:0|1|2)$#) {
				delete $open_fds{$fd};
			}
		} elsif ($line =~ m#^read\((?<fd>\d+),\s*(?:(?:".*?"(?:\.\.\.)?)|$hex),\s+(?<len>\d+)\)\s*=\s*(?<readchars>$ret)(?:\s*(?<error>.*))#) {
			#read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\30\0\0\0\0\0\0"..., 832) = 832
			#read(10, 0x7ffd3f49825f, 1)             = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
			if(exists $+{error} && $+{error}) {
				printmsg "Reading $+{len} from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}".error($+{error});
			} else {
				printmsg "Reading $+{len} from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}"; 
			}
		} elsif ($line =~ m#^arch_prctl\((?<mode>$mode),\s*(?<mem>$hex_or_num_or_null)\)\s*=\s*(?<ret>$num)#) {
			#arch_prctl(ARCH_SET_FS, 0x7fab7dfa5f80) = 0
			printmsg "arch_prctl($+{mode}, $+{mem}) = $+{ret}";
		} elsif ($line =~ m#^munmap\((?<mem>$hex_or_num_or_null),\s*(?<size>$num)\)\s*=\s*(?<ret>$num)#) {
			#munmap(0x7fab7dfa9000, 344055)          = 0
			printmsg "munmap($+{mem}, $+{size}) = $+{ret}";
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
		} elsif ($line =~ m#^readlink\("(?<link>[^"]+)",\s*(?<to>(?:".*?"+|$hex)),\s*(?<len>\d+)\)\s*=\s*(?<ret>$ret)(?:\s*(?<error>.*))#) {
			#readlink("/proc/self/fd/0", "/dev/pts/2", 4095) = 10
			#readlink("/usr/bin/python3.5", 0x7fffdf0f3b50, 4096) = -1 EINVAL (Invalid argument)
			printmsg "Reading symbolic link $+{link} (to $+{to}), length: $+{len}. Returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^stat\("(?<file>[^"]+)",\s*.+\)\s*=\s*(?<ret>\d*)#) {
			#stat("/dev/pts/2", {st_mode=S_IFCHR|0600, st_rdev=makedev(136, 2), ...}) = 0
			printmsg "stat'ting $+{file}, returned $+{ret}";
		} elsif ($line =~ m#^lstat\("(?<file>.+?)",\s*.+\)\s*=\s*(?<ret>\d*)#) {
			#lstat("/home/norman/.oh-my-zsh/custom/plugins/zsh-autosuggestions", {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
			#lstat("\"^opn", 0x55d2799deac0)         = -1 ENOENT (No such file or directory)
			printmsg "lstat'ting $+{file}, returned $+{ret}";
		} elsif ($line =~ m#^fcntl\((?<fd>\d+),\s*(?<mode>$hex_or_num_or_null_or_mode)(?:,\s*(?<param>$hex_or_num_or_null_or_mode))?\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
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
			$pipe_fds{$+{pipe1}} = $+{pipe2};
		} elsif ($line =~ m#^pipe2\(\[(?<pipe1>\d*),\s*(?<pipe2>\d+)],\s*(?<mode>$mode)\)\s*=\s*(?<ret>\d+)(?:\s*(?<error>.*))#) {
			#pipe2([3, 4], O_CLOEXEC)                = 0
			printmsg "Opening pipe2 $+{pipe1}, set to $+{pipe2} with mode $+{mode}".error($+{error});
			$pipe_fds{$+{pipe1}} = $+{pipe2};
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
		} elsif ($line =~ m#^socket\((?<domain>$mode),\s*(?<type>$mode),\s*(?<protocol>$mode)\)\s*=\s*(?<ret>\d+)#) {
			#socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 11
			#socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
			printmsg "Opening socket $+{domain} with type $+{type} and protocol $+{protocol}, returned $+{ret}";
			$open_fds{$+{ret}} = $+{domain};
		} elsif ($line =~ m#^connect\((?<socketfd>\d+),\s*[^\)]+\)\s*=\s*(?<ret>$num)\s*((?<error>.*))?#) {
			#connect(11, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
			printmsg "Connecting to $+{socketfd} (-> ".$open_fds{$+{socketfd}}."), returned $+{ret}".error($+{error});
		} elsif ($line =~ m#^lseek\((?<fd>\d+),\s*(?<offset>$num),\s*(?<mode>$mode)\)\s*=\s*(?<ret>$num)(?:\s*(?<error>.*))#) {
			#lseek(3, 0, SEEK_CUR)                   = 0
			#lseek(11, 0, SEEK_CUR)                  = 0
			printmsg "lseek'ing $+{fd} (-> ".fd_to_filename($+{fd})."), mode = $+{mode}, returned: $+{ret}".error($+{error});
		} elsif ($line =~ m#^uname\(#) {
			#uname({sysname="Linux", nodename="alanwatts", ...}) = 0
			printmsg "uname called";
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
		} elsif ($line =~ m#^set_tid_address\((?<mem>$hex)\)\s*=\s*(?<ret>$num)#) {
			#set_tid_address(0x7f59309531d0)         = 31114
			debug "Set pointer to thread id $+{mem} returned $+{ret}";
		} elsif ($line =~ m#^set_robust_list\((?<mem>$hex),\s*(?<size>\d+)\)\s*=\s*(?<ret>\d*)#) {
			#set_robust_list(0x7f59309531e0, 24)     = 0
			debug "get_robust_list($+{mem}) = $+{ret}";
		} elsif ($line =~ m#^exit_group\((?<exit>\d+)\)\s*=\s*(?<ret>$ret)#) {
			#exit_group(0)                           = ?
			debug "Exiting with $+{exit} returned $+{ret}";
		} elsif ($line =~ m#^(\+\+\+|---)(.*)\1#) {
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
		} elsif ($line =~ m#^kill\((?<pid>$num),\s*(?<signal>$mode)\)\s*=\s*$ret(?:\s*(?<error>.*))#) {
			#kill(9998, SIG_0)                       = 0
			#kill(-10018, SIG_0)                     = -1 ESRCH (No such process)
			if(exists $+{error} && $+{error}) {
				printmsg "Sending $+signal to $+pid".error($+{error});
			} else {
				printmsg "Sending $+signal to $+pid";
			}
		} elsif ($line =~ m#^write\((?<fd>\d+),.*?,\s*(?<len>\d+)\)\s*=\s*(?<ret>$ret)#) {
			#write(1, "ack-grep not found\n", 19)    = 19
			printmsg "Writing $+{len} characters to fd $+{fd} ( -> ".fd_to_filename($+{fd})."), returned $+{ret}";
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
		} elsif ($line =~ m#^alarm\((?<time>\d+)\)\s*=\s*(?<ret>$num)#) {
			#alarm(0)                                = 0
			printmsg "Called alarm($+{time}), returned $+{ret}";
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
			printmsg "bind'ing $+{socket}, returned $ret".error($+{error});
		} elsif ($line =~ m#^\s*$#) {
		} else {
			chomp $line;
			die "Unknown line $i:\n".color("red").$line.color("reset")."\n";
		}
		$i++;
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

	if(exists $open_fds{$+{fd}}) {
		return $open_fds{$fd};
	} else {
		return color("red")."!!! unknown_fd !!!".color("blue");
	}
}

sub error {
	my $error = shift;
	chomp $error;

	if($error) {
		return ". ".color("on_red")."ERROR: $error".color("blue")." ";
	} else {
		return '';
	}
}
