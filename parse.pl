#!/usr/bin/perl

sub debug (@);
sub printmsg (@);
sub errormsg ($);

use strict;
use warnings FATAL => "all";
use autodie;
use Hash::Util;
use Data::Dumper;
use Term::ANSIColor;
use Memoize;

memoize 'get_man_page';

my %all_errors = ();

my %options = (
	filename => undef,
	debug => 0,
	show_only_errors => 0,
	die_on_error => 1,
	show_most_commons_errors => 1
);

analyze_args(@ARGV);

	
my %open_fds = (
	0 => 'STDIN',
	1 => 'STDOUT',
	2 => 'STDERR'
);

my (
	$command_color, 
	$result_color, 
	$reset, 
	$underline, 
	$underline_red, 
	$red, 
	$debug_color, 
	$default_color
) = (
	color("cyan"), 
	color("underline green"), 
	color("reset"), 
	color("underline"), 
	color("underline red"), 
	color("red"), 
	color("magenta"), 
	color("yellow")
);

main();

sub main {
	debug "main()";
	debug Dumper \%options;
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
	my $retval = qr/\s*=\s*$ret(?:\s*(?<error>(?<errorcode>[A-Z0-9]+)\s+(?:.*)))?/;

	my $i = 0;

	while (my $line = <$fh>) {
		$line =~ s#^(\d*\s*)*##g;
		chomp $line;
		$i++;

		next if skip_line($line);
		debug join('', map { chomp $_; $_ } $line);

		if(check_balanced_objects($line) ne "OK") {
			warn "ERROR: In line >>>\n$line<<< there are unbalanced characters! Skipping this line.\n";
			next;
		}
		if($line =~ m#^(?<funcname>open)\("(?<filename>.*?)"(?:,\s*(?<rest>.*))?\)$retval#g) {
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "Opening $+{filename} in mode $+{rest}, returned fd $+{ret}".$error;
			}
			if(!$error) {
				$open_fds{$+{ret}} = $+{filename};
			}
		} elsif($line =~ m#^(?<funcname>openat)\((?<mode>$mode),\s*"(?<filename>.*?)"(?:,\s*(?<rest>.*))?\)$retval#g) {
			#openat(AT_FDCWD, "/sw/taurus/libraries/python/3.6-anaconda4.4.0/lib/python3.6/site-packages", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 4
			my $error = get_error_string(\%+);
			printmsg "openat($+{mode}, $+{filename}, $+{rest}) = $+{ret}".$error;
			if(!$error) {
				$open_fds{$+{ret}} = $+{filename};
			}
		} elsif ($line =~ m#^(?<funcname>close)\((?<fd>\d+)\)$retval#) {
			#close(3)
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "Closing $+{fd} (to ".fd_to_filename($+{fd})."), returned $+{ret}".$error;
			}
			my $fd = $+{fd};
			if($fd !~ m#^(?:0|1|2)$#) {
				delete $open_fds{$fd};
			}
		} elsif ($line =~ m#^(?<funcname>read)\((?<fd>\d+),\s*(?:(?:".*?"(?:\.\.\.)?)|$hex)(?:,\s+(?<len>\d+))?\)$retval#) {
			#read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\300\30\0\0\0\0\0\0"..., 832) = 832
			#read(10, 0x7ffd3f49825f, 1)             = ? ERESTARTSYS (To be restarted if SA_RESTART is set)
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				if(exists $+{len} && defined $+{len}) {
					printmsg "Reading $+{len} from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}".$error; 
				} else {
					printmsg "Reading from $+{fd} (".fd_to_filename($+{fd})."), got $+{ret}".$error; 
				}
			}
		} elsif ($line =~ m#^(?<funcname>ioctl)\((?<fd>$num),\s*(?<mode>$mode)(?:,\s*.*?)?\)$retval#) {
			#ioctl(0, TCGETS, {B38400 opost isig icanon echo ...}) = 0
			#ioctl(10, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig -icanon -echo ...}) = 0
			#ioctl(2, TCGETS, 0x7ffd3f481be0)        = -1 ENOTTY (Inappropriate ioctl for device)
			my $error = get_error_string(\%+);

			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "ioctl($+{fd} [ -> ".fd_to_filename($+{fd})."], ...) = $+{ret}".$error;
			}
		} elsif ($line =~ m#^(?<funcname>fcntl)\((?<fd>\d+),\s*(?<mode>$hex_or_num_or_null_or_mode)(?:,\s*(?<param>$hex_or_num_or_null_or_mode))?\)$retval#) {
			#fcntl(3, F_DUPFD, 10)                   = 10
			my $error = get_error_string(\%+);
			printmsg "manipulating fd with fcntl $+{fd} (-> ".fd_to_filename($+{fd})."), mode: $+{mode}, returned $+{ret}".$error;
		} elsif ($line =~ m#^(?<funcname>pipe)\(\[(?<pipe1>\d*),\s*(?<pipe2>\d+)]\)$retval#) {
			#pipe([3, 4])                            = 0
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "Opening pipe $+{pipe1}, set to $+{pipe2}".$error;
			}
			$open_fds{$+{pipe1}} = $+{pipe2};
		} elsif ($line =~ m#^(?<funcname>pipe2)\(\[(?<pipe1>\d*),\s*(?<pipe2>\d+)],\s*(?<mode>$mode)\)$retval#) {
			#pipe2([3, 4], O_CLOEXEC)                = 0
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "Opening pipe2 $+{pipe1}, set to $+{pipe2} with mode $+{mode}".$error;
			}
			$open_fds{$+{pipe1}} = $+{pipe2};
		} elsif ($line =~ m#^(?<funcname>dup)\((?<fd>\d+)\)$retval#) {
			#dup(0)                                  = 5
			my $error = get_error_string(\%+);
			printmsg "dup fd $+{fd} (-> ".fd_to_filename($+{fd}).") to new fd $+{ret}".$error;
			if(exists $open_fds{$+{ret}}) {
				$open_fds{$+{newfd}} = $open_fds{$+{ret}};
			}
		} elsif ($line =~ m#^(?<funcname>dup2)\((?<oldfd>\d+),\s*(?<newfd>\d*)\)$retval#) {
			my $error = get_error_string(\%+);
			#dup2(3, 1)                              = 1
			printmsg "dup2 fd $+{oldfd} (-> ".fd_to_filename($+{oldfd}).") to newfd $+{newfd}, returned $+{ret}".$error;
			if(defined $open_fds{$+{oldfd}}) {
				$open_fds{$+{newfd}} = $open_fds{$+{oldfd}};
			}
		} elsif ($line =~ m#^(?<funcname>socket)\((?<domain>$mode),\s*(?<type>$mode),\s*(?<protocol>$mode)\)$retval#) {
			#socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 11
			#socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
			#socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = -1 EACCES (Permission denied)
			my $error = get_error_string(\%+);
			printmsg "Opening socket $+{domain} with type $+{type} and protocol $+{protocol}, returned $+{ret}".$error;
			$open_fds{$+{ret}} = $+{domain};
		} elsif ($line =~ m#^(?<funcname>connect)\((?<socketfd>\d+),\s*.*?\)$retval#) {
			#connect(11, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
			#connect(4, {sa_family=AF_INET, sin_port=htons(30290), sin_addr=inet_addr("172.24.138.246")}, 16) = -1 EINPROGRESS (Operation now in progress)
			my $error = get_error_string(\%+);
			printmsg "Connecting to $+{socketfd} (-> ".fd_to_filename($+{socketfd})."), returned $+{ret}".$error;
		} elsif ($line =~ m#^(?<funcname>lseek)\((?<fd>\d+),\s*(?<offset>$num),\s*(?<mode>$mode)\)$retval#) {
			#lseek(3, 0, SEEK_CUR)                   = 0
			#lseek(11, 0, SEEK_CUR)                  = 0
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "lseek'ing $+{fd} (-> ".fd_to_filename($+{fd})."), mode = $+{mode}, returned: $+{ret}".$error;
			}
		} elsif ($line =~ m#^(?<funcname>newfstatat)\((?<fd>\d+),\s*"(?<path>.*?)",.*?\)$retval#) {
			#newfstatat(13, "sys/bus/pci/devices/0000:07:00.1//mic", 0x7ffd54c66a30, AT_SYMLINK_NOFOLLOW) = -1 ENOENT (No such file or directory)
			my $error = get_error_string(\%+);
			printmsg "newfstatat called for fd $+{fd} [ -> ".fd_to_filename($+{fd})."]. Returned $+{ret}".$error;
		} elsif ($line =~ m#^(?<funcname>getdents)\((?<fd>\d+),.*?\)$retval#) {
			#getdents(3, /* 276 entries */, 32768)   = 10096
			my $error = get_error_string(\%+);
			printmsg "Get directory entries for fd $+{fd} (-> ".fd_to_filename($+{fd})."), returned $+{ret}".$error;
		} elsif ($line =~ m#^(?<funcname>getdents64)\((?<fd>\d+),.*?\)$retval#) {
			#getdents64(4, /* 9 entries */, 280) = 216
			my $error = get_error_string(\%+);
			printmsg "Get directory entries (getdents64) for fd $+{fd} (-> ".fd_to_filename($+{fd})."), returned $+{ret}".$error;
		} elsif ($line =~ m#^(\+\+\+|---)(.*)#) {
			#+++ exited with 0 +++
			#--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=9988, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
			printmsg "Got weird line $2";
		} elsif ($line =~ m#^(?<funcname>write)\((?<fd>\d+),\s*(?<rest>.*?)\)$retval#) {
			#write(1, "ack-grep not found\n", 19)    = 19
			#write(2, "INFO:hyperopt.mongoexp:PROTOCOL "..., 38) = -1 EPIPE (Broken pipe)
			my $error = get_error_string(\%+);
			if(!$options{show_only_errors} || ($options{show_only_errors} && $error)) {
				printmsg "Writing $+{rest} to fd $+{fd} ( -> ".fd_to_filename($+{fd})."), returned $+{ret}".$error;
			}
		} elsif ($line =~ m#^(?<funcname>recvfrom)\((?<socket>\d+),.*\)$retval#) {
			#recvfrom(4, "\340\0\0\0\313\234\0\0{\337\2001\335\7\0\0", 16, 0, NULL, NULL) = 16
			my $error = get_error_string(\%+);
			printmsg "Receive from $+{socket} ( -> ".fd_to_filename($+{socket})."). Returned $+{ret}".$error;
		} elsif ($line =~ m#^(?<funcname>socket)\((?<socket>$mode)(?<rest>.*)\)$retval#) {
			#socket(AF_LOCAL, SOCK_STREAM, 0)  = 22
			my $error = get_error_string(\%+);
			printmsg "Opened socket $+{socket}$+{rest}. Returned $+{ret}".$error;
			if(!$error) {
				$open_fds{$+{ret}} = $+{socket};
			}
		} elsif($line =~ m#^(?<funcname>[a-z0-9_]+)\((?<firstparam>.*?)\)$retval#g) {
			#get_mempolicy(NULL, NULL, 0, NULL, 0) = 0
			my $error = get_error_string(\%+);
			if(($options{show_only_errors} && $error) || !$options{show_only_errors}) {
				printmsg "$command_color$+{funcname}($+{firstparam})$reset = $result_color$+{ret}$reset".$error;
			}
		} elsif ($line =~ m#^\s*$#) {
			# Do nothing intentionally with empty lines
		} else {
			chomp $line;
			errormsg "Unknown line $i\n".$red.$line.$reset."\n";
		}
	}
	close $fh;
}

sub errormsg ($) {
	my $msg = shift;
	if($options{die_on_error}) {
		die $msg;
	} else {
		warn $msg;
	}
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
		} elsif (m#^--show_only_errors$#) {
			$options{show_only_errors} = 1;
		} elsif (m#^--dont_die_on_error$#) {
			$options{die_on_error} = 0;
		} elsif (m#^--dont_show_most_commons_errors$#) {
			$options{show_most_commons_errors} = 0;
		} elsif (m#^--help$#) {
			_help(0);
		} else {
			warn "Unknown parameter $_";
			_help(1);
		}
	}
}

sub _help {
	my $exit_code = shift;

	print <<'EOF';
StupidStraceParser

=============================================================================================

This is a simple strace-log-parser that outputs a colorful version of any strace-log.
Also, this decodes names file handle ids to file names whenever possible.

These are it's options:

	--help					This help menu
	--debug					Enables debug-output
	--filename=logfile			The name of the log file
	--show_only_errors			Show only lines that contain errors and open/
						closing FDs and such
	--dont_die_on_error			Warn instead of die when encountering a line
						this script cannot read
	--dont_show_most_commons_errors		Don't how the most common errors at the end of
						the script.

EOF

	exit($exit_code);
}

sub debug (@) {
	if($options{debug}) {
		foreach (@_) {
			warn $debug_color.join("\n", map { $red."DEBUG: ".$debug_color.$_.$reset; } split(/\R/, $_)).$reset."\n";
		}
	}
}

sub printmsg (@) {
	my $msg = shift;
	print $default_color.$msg.$reset."\n";
}	

sub fd_to_filename {
	my $fd = shift;
	debug "fd_to_filename($fd)";

	if(exists $open_fds{$fd}) {
		return $underline.$open_fds{$fd}.$reset.$default_color;
	} else {
		return $red."!!! ERROR: unknown_fd !!!".$default_color;
	}
}

sub get_error_string {
	my $plus = shift;
	debug "get_error_string(".Dumper($plus).")";
	return '' unless exists($plus->{error});
	my ($manpage, $errors) = get_man_page($+{funcname});
	my $error = error(\%+, $errors);
	if($error) {
		$all_errors{$error}++;
		return $error;
	} else {
		return '';
	}
}

sub error {
	my $plus = shift;
	unless(exists $plus->{error}) {
		debug "error(...)";
		return;
	}
	debug "error(".Dumper($plus).")";
	my $errors = shift;

	my $error = $plus->{error};
	my $errorcode = $plus->{errorcode};

	chomp $error;

	if($error) {
		my $str = $reset."\n-> ".$underline_red."ERROR: $error".$reset;
		if(exists $errors->{$errorcode}) {
			$str .= "\n-> ".$errors->{$errorcode};
		}
		return $str;
	} else {
		return '';
	}
}

sub get_man_page {
	my $name = shift;
	debug "get_man_page($name)";

	my $contents = qx(man 2 $name 2> /dev/null);
	$contents =~ s/^(?:.*\n){5}//;
	return unless $contents;

	my %parsed = ();
	my $title = '';

	foreach my $line (split /\R/, $contents) {
		chomp $line;
		if($line =~ m#^[A-Z][A-Z ]+$#) {
			$title = $line;
			$parsed{$title} = '';
		} else {
			$line =~ s#^\s*##g;
			$parsed{$title} .= "$line\n";
		}
	}

	foreach my $key (keys %parsed) {
		chomp $parsed{$key};
		chomp $parsed{$key};
	}

	my %errors = ();
	if(exists $parsed{ERRORS}) {
		foreach my $line (split /\R\R/, $parsed{ERRORS}) {
			if($line =~ m#^([A-Z0-9]+)\s+(.*)#gism) {
				my $error = $1;
				my $desc = $2;
				$desc = join(' ', split(/\R/, $desc));
				$desc =~ s#\s{2,}# #g;
				$desc =~ s#‐ ##g;
				if(exists $errors{$error}) {
					$errors{$error} .= "\n-> ".$underline."ALTERNATIVE MEANING".$reset.":\t".$desc;
				} else {
					$errors{$error} = $underline."MEANING".$reset.":\t\t".$desc;
				}
			}
		}
	}

	return \%parsed, \%errors;
}

sub check_balanced_objects {
	my $string = shift;
	debug "check_balanced_objects($string)";

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

sub skip_line {
	my $line = shift;
	debug "skip_line($line)";

	if($line =~ m#^\s*$#) {
		debug "Skipping empty lines.";
		return 1;
	}

	if($line =~ m#^[a-z]+\d+\s+#) {
		debug "Line does not start with letters. Skipping it.";
		return 1;
	}
	if($line =~ m#^[^a-z0-9]#) {
		debug "Line does not start with letters. Skipping it.";
		return 1;
	}
	if($line !~ m#\s+=\s+#) {
		debug "Line does not seem like a function call. Skipping it.";
		return 1;
	}
	if($line =~ m#<unfinished \.\.\.># || $line =~ m#<\.\.\. .* resumed>#) {
		debug "Skipping threaded lines containing 'unfinished' or 'resumed'.";
		return 1;
	}

	return 0;
}

END {
	if ($options{show_most_commons_errors} && keys %all_errors) {
		print "\n\n\n".color("black on_red")."Most common errors:$reset\n";
		foreach my $error (sort { $all_errors{$a} <=> $all_errors{$b} } keys %all_errors) {
			print "\t$error\n-> Times encountered: $all_errors{$error}\n";
		}
	}
}
