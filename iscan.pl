#!/usr/bin/perl
#
# (c) 2013 The Infinity Network (http://theinfinitynetwork.org/)
#
# finds malicious junk
#

use strict;

use DBI;
use File::Find;

no warnings 'File::Find';
 
my @dirs = (
	"/bin/",
	"/sbin/",
	"/usr/",
	"/tmp/",
	"/boot/",
	"/dev/",
	"/etc/",
	"/sys/",
	"/opt/",
	"/var/");

my @vuln = (
	'\.\.\.',
	'\/\.ssh',
	'\.ssh\/',
	'\.kinetic',
	'worm\/',
	'\/\-sh',
	'arobia',
	'\/lkm',
	'bktools',
	'\/bex',
	'wted',
	'xfss',
	'dsx',
	'dika',
	'fuckit',
	'ivtype',
	'lports',
	'toolz',
	'gaskit',
	'funces',
	'\/ixinit',
	'h4x',
	'kbeast',
	'knark',
	'\/xsf\/',
	'xchk',
	'\/ph1',
	'uNF',
	'\/unf\/',
	'rkit',
	'zup',
	'tk02',
	'lpstree',
	'lkill',
	'\/ldu',
	'lnetstat',
	'vadim',
	'scannah',
	'ttyo',
	'bugtraq',
	'cinik',
	'chrps',
	'linsniff',
	'charbd',
	'initsk',
	'initxr',
	'sk12',
	'S23kmdac',
	'tehdrak',
	'\/MG\/',
	'backsh',
	'izbtrag',
	'sksniff',
	'TeleKiT',
	'hda06',
	'lsniff',
	't0rn',
	'lib\/lib\/',
	'buloc',
	'tcpshell',
	'libtcs',
	'wold',
	'whoold',
	'backdoors',
	'sshd2_config',
	'xxxxxx',
	'tulz',
	'lulz',
	'ras2\/',
	'sourcemas',
	'xmx',
	'kdx',
	'\/psr',
	'\/ice\/'
	);

find({wanted=> \&file_callback, follow => 0}, @dirs);

sub file_callback
{
	-l && !-e && next;
	my $file = $File::Find::name;

	if ($file) { foreach my $v(@vuln) { print (localtime() . " *warning* /" . $v . "/ " . $file . "\n") if ($file =~ /$v/); } }

}
