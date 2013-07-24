#!/usr/bin/perl
## SCARY's scheduler (multiprocessing is fucked and it will be for some time (no hardware for that at the moment anyway))
use strict;
my $victims_dir='/home/scary/victims/';
my @alert_mail=('ewilded@gmail.com');
my $mail_from='ewilded@gmail.com';
my @alert_filters=('\\[XSS\\]','\\[EXEC\\]','\\[EVAL\\]','\\[SHELL\\]','\\[SQL\\]','\\[FOPEN\\]','\\[EXEC-NULLBYTE_REQUIRED\\]','\\[FOPEN-NULLBYTE_REQUIRED\\]', '\\[EXEC-PROBABLY\\]','\\[EVAL-PROBABLY\\]','\\[SHELL-PROBABLY\\]','\\[SQL-PROBABLY\\]','\\[FOPEN-PROBABLY\\]','\\[FOPEN-PROBABLY-NULLBYTE_REQUIRED\\]','\\[EXEC-PROBABLY-NULLBYTE_REQUIRED\\]');
## add -PROBABLY filters as well
start_again:
my @archives=(`ls $victims_dir/*.t*gz`,`ls $victims_dir/*.rar`, `ls $victims_dir/*.zip`, `ls $victims_dir/*.bz2`);
foreach my $archive(@archives)
{
	chomp($archive);
	my @archive_parts=split('/',$archive);
	$archive=$archive_parts[scalar(@archive_parts)-1];
	my $dir_name=$archive;
	$dir_name=~s/\.tar\.bz2$//;
	$dir_name=~s/\.tar\.gz$//;
	$dir_name=~s/\.tgz$//;
	#$dir_name=~s/\.gz$//;
	$dir_name=~s/\.zip$//;
	$dir_name=~s/\.rar$//;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
	$dir_name.="-$year-$mon-$mday"; ## append date to avoid confusion about project being up to date
	if(-d $dir_name)
	{
		print "$dir_name is already processed.\n";
	}
	else
	{
		print "$victims_dir/$dir_name does not exists.\n";
		`mkdir $victims_dir/$dir_name`;
		`mv $victims_dir/$archive $victims_dir/$dir_name/`;
		my $new_archive_path="$victims_dir/$dir_name/$archive";
		print "Unpacking $new_archive_path.\n";
		
		system("cd $victims_dir/$dir_name; tar zxfv $new_archive_path") if($new_archive_path=~/tar\.gz$/||$new_archive_path=~/tgz$/);
		system("cd $victims_dir/$dir_name; tar jxfv $new_archive_path") if($new_archive_path=~/tar\.bz2$/);
		system("cd $victims_dir/$dir_name; unzip $new_archive_path") if($new_archive_path=~/\.zip$/);
		system("cd $victims_dir/$dir_name; unrar e $new_archive_path") if($new_archive_path=~/\.rar$/);
		
		print "Unacking done, starting SCARY.\n";
		my $log="$victims_dir/$dir_name.AUTO_SCARY.log";
		my $alert_log="$victims_dir/$dir_name.AUTO_SCARY.ALERT";
		system("touch $victims_dir/$dir_name/.SCARED"); # lockfile
		system("perl scary.pl auto_sca $victims_dir/$dir_name>$log");
		## when it's done
		
		### Ok, here are the filters
		my @alert=();
		foreach my $alert_filter(@alert_filters)
		{
			push(@alert,`grep '$alert_filter' $log`);			
		}
		if(scalar(@alert)>0)
		{
			open(F,">$alert_log");
			print F "Subject: SCARY alert for $dir_name\n";
			foreach my $alert_line(@alert)
			{
				print F $alert_line;
			}
			close(F);
			foreach my $alert_mail_addr(@alert_mail)
			{
				print "$alert_log not empty, mailing results to $alert_mail_addr.\n";
				print "sendmail -f $mail_from $alert_mail_addr<$alert_log\n"; ## syntax for sendmail is kinda fucked here too
				`sendmail -f $mail_from $alert_mail_addr<$alert_log`;
			}
			print `cat $alert_log`;
		}
		system("touch $victims_dir/$dir_name/.SCARED_DONE"); # lockfile
		print "$dir_name is done.\n";
	}
}
sleep(5);
goto start_again; ## this introduces support for collector.pl working in the same time for continuous SCARY-ing ;D