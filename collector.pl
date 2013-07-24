#!/usr/bin/perl
## SCARY's collector
## currently sourceforge only
#http://sourceforge.net/directory/language:php/
#http://sourceforge.net/directory/language%3Aphp/?page=9
## We are experiencing an issue with collector, looks like sourceforge detects this is an automated web client and serves only first page regardless to the page parameter. Probably we'll replace this with chickenfoot or sth.

use strict;
use HTTP::Request::Common qw(POST);
use HTTP::Request; 
use HTTP::Cookies;
use LWP::UserAgent;
use LWP::Simple;
use Compress::Zlib;


my $max_subpages=20; ## number of pages with results
my $max_meanpage_delay=20; ## 15 minutes
my $max_meandownload_delay=30; ## 2 minutes
my $min_download_page=10; ## do not go lower than these subpages
my $repo='google';
my $victims_dir='/home/acid/src/Perl/DiveInferno/victims/';
my $agent="Opera/9.80 (X11; Linux x86_64; U; en) Presto/2.10.229 Version/11.61";
my $ua = LWP::UserAgent->new or die;
my $cookie_jar = HTTP::Cookies->new();
$ua->cookie_jar($cookie_jar);
my $req;
my $res;
my $can_accept = HTTP::Message::decodable;
my %repos;

sub goto_page_rand		## [READY]
{
	my $r=int(rand($max_meanpage_delay));
	$r++ if($r eq 0);
	$r+=$min_download_page;
	$r*=10;  ## gooogle
	my $link;
	$link="http://sourceforge.net/directory/language%3Aphp/?page=$r" if($repo eq 'sourceforge'); 
	$link="http://code.google.com/hosting/search?q=label%3APHP&filter=0&mode=&start=$r";
	
	print "Going to page $link... (can accept: $can_accept)\n";
	$req = HTTP::Request->new(GET => $link);
	$req->header('Accept-Encoding' => $can_accept);
	$res=$ua->request($req);
	my @project_names=();
	## now, let's get the project's list
	#	print $res->content."\n";
	#my $content=$res->content;
	### probably no referrer or cookies support causes this problem
	my $content=$res->decoded_content;
	print "Saving content into $repo.content.debug\n";
	open(chuj,">$repo.content.debug");
	print chuj $content;
	close(chuj);
	die('Examine it!');
	#while($content=~/<span itemprop="name">(\w+)<\/span>/sg) ## sourceforge
	while($content=~/href="\/(\w+)\/(.*?)\/" style="font-size:medium">(.*?)&nbsp;- &nbsp;(.*?)<\/a>/)
	{
		my $project_name=$1;
		print "Estimated project name: $project_name\n";
		push(@project_names,$project_name);
		sleep(1);
	}
	if(scalar(@project_names) eq 0)
	{
		print "What the fuck, no projects fonud.\n";
		die;
	}
	print "Ok, now going to download them, one after another.\n";
	foreach my $project_name(@project_names)
	{
		if(&project_downloaded($project_name) eq 1)
		{
			print "Project $project_name already downloaded.\n";
			next;
		}
		my $delay2=int(rand($max_meandownload_delay));
		print "Going to sleep for $delay2 before hitting http://sourceforge.net/projects/$project_name/?source=directory\n";
		sleep($delay2);
		my $ua2=LWP::UserAgent->new or die;
		my $cookie_jar2 = HTTP::Cookies->new();
		$ua2->cookie_jar($cookie_jar2);
		my $project_download_page="http://code.google.com/p/$project_name/downloads/list";
		my $req2 = HTTP::Request->new(GET => $project_download_page);
		my $res2=$ua2->request($req2);
		
		while($res2->content=~<a href="//$project_name.googlecode.com/files/(.*?)"/)
		{
			my $filename=$1;
			print "Found file for download: http://$project_name.googlecode.com/files/$filename\n";
			### here is the wget
		}
		#if(!($res2->content=~/<a href="(.*?)" class="direct-download">/sg)) ## sourceforge
		#{
		#	print "Could not find download link in ".$res2->content."\n";
		#	next;
		#}
		my $download_link=$1;
		print "Found direct download URL $download_link. Downloading...\n";
		if(&download_project($download_link,$project_name) eq 1)
		{
			print "Success.\n";
		}
		else
		{
			print "Failed!\n";
		}
	}
}

sub download_project		## [READY]
{
	my $link=shift;
	my $project_name=shift;
	my $wdir=`pwd`;
	mkdir($victims_dir/$project_name);
	`wget $link -O $victims_dir/$project_name/`;
	my $project_archive=`ls $victims_dir/$project_name/`;
	chomp($project_archive);
	print "Downloaded project archive: $victims_dir/$project_name/$project_archive\n";
	chdir("$victims_dir/$project_name");
	if($project_archive=~/tar\.gz$/||$project_archive=~/tgz$/)
	{
		system("tar zxfv $project_archive");
		chdir($wdir);
		return 1;
	}
	if($project_archive=~/tar\.bz2$/)
	{
		system("tar jxfv $project_archive");
		chdir($wdir);
		return 1;
	} 
	if($project_archive=~/\.zip$/)
	{
		system("unzip $project_archive");
		chdir($wdir);
		return 1;
	} 
	chdir($wdir);
	print "$project_archive - unknown archive format.\n";
	return 0;
}

sub project_downloaded ## [READY]
{
	my $project_name=shift;
	print "Checking for $victims_dir/$project_name\n";
	return 1 if(-d "$victims_dir/$project_name");
	return 0;
}

## RUN [READY]
$ua->agent($agent); 
$ua->timeout(20);
while(1)
{
	&goto_page_rand();
	my $delay=int(rand($max_meanpage_delay));
	print "Sleeping for $delay meanpage seconds.\n";
	sleep($delay);
}