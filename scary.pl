#!/usr/bin/perl
# SCARY - Source Code Analyzer Replaces You
# coded by ewilded
# Licensed under the GPL v 3 license.
# For features and capabilities, see README for details.

package scary;
use strict;
use IO::Handle;
use Switch;
use Data::Dumper;
use Term::ANSIColor;

my $version='current';
## CONFIG
my $max_nested_expressions=30;
my $max_nested_includes=10;
## output configuration
my %debug_config;
$debug_config{'INCLUDE'}=1;
$debug_config{'REGISTER'}=1;
$debug_config{'CALL'}=1;
$debug_config{'DEBUG'}=1;
$debug_config{'FUNCTION_DEFINITION'}=1;
$debug_config{'EXPRESSION'}=1;
$debug_config{'LIST_VARIABLES'}=1;
$debug_config{'MERGE'}=1;
$debug_config{'ERROR'}=1;
$debug_config{'WARNING'}=1;
$debug_config{'RESOLVE'}=1;
$debug_config{'MATCH'}=1;
$debug_config{'SUMMARY'}=1;
# vulnerable functions grouped by the kind of security issue (i'll extend this list later with the help of php.net :D)
my @exec_vulnerable_functions=('include', 'include_once','require_once','require'); 
my @sql_vulnerable_functions=('mysql_query','mysqli_query','mysql_unbuffered_query','oci_execute','cubrid_execute','sqlsrv_prepare','pg_prepare');
my @xss_vulnerable_functions=(@sql_vulnerable_functions, ('echo','print','printf','print_r','var_dump','fwrite','fputs','file_put_contents','flush','ob_flush','fputcsv'));
my @upload_vulnerable_functions=('file_put_contents', 'move_uploaded_file'); ## not implemented
my @fopen_vulnerable_functions=('file_get_contents','fopen','file','readfile','copy');
my @shell_vulnerable_functions=('exec', 'shell_exec', 'system', 'popen', 'passthru', 'proc_open', 'pcntl_proc_open','pcntl_exec','expect_popen','ssh2_exec');
my @eval_vulnerable_functions=('eval','create_function','register_shutdown_function','register_thick_function','forward_static_call','forward_static_call_array','call_user_func', 'call_user_func_array','ini_set','unserialize'); # create_function DEPRECATED as of PHP 7.2.0 | arbitrary ini_set can be abused in a number of ways, e.g. by setting the  auto_append_file | unserialize added temporarily, will create a separate category for it | interestingly, 'eval' cannot be registered with register_shutdown_function, but shell_exec can - thus adding register_shutdown_function here, also samae goes for call_user_func and call_user_func_array :D - what about set_error_handler and set_exception_handler? what about UI Execution scheduler?
## List of sanitizing and checking functions, which use on user supplied input decreases probability of found security issue
my @filtering_functions=('preg_replace','ereg_replace','eregi_replace','str_replace','strtr', 'str_ireplace','substr_replace');
## Universal sanitation functions
my @checking_functions=('preg_match','strstr','strpos','ereg', 'eregi');
my @array_functions=('array_key_exists','in_array','array_search','switch','filter_var','md5','basename','ctype_ alnum','ctype_ alpha','ctype_ cntrl','
ctype_digit','ctype_xdigit','intval','md5','mktime'); ## functions that give limited results
my @escape_shell_functions=(); # ('escapeshellarg','escapeshellcmd'); ## for now let's skip these and leave all relevant calls for manual inspection, allowing false positives
my @sql_num_checking_functions=('is_numeric','is_int','intval');
#13:37 <&condy> albo rzutowanie (int)
## add is_uploaded_file and implement file uploads
my @xss_filtering_functions=('htmlspecialchars', 'htmlentities');
my @sql_filtering_functions=('addslashes', 'mysql_escape_string', 'mysql_real_escape_string');
my @sql_num_filtering_functions=('int','settype','intval','(int)','(float)');  # commented out 'prepare', moving it to vuln functions - as this solely depends on in WHAT argument the user-supplied value lands, so we now favor false positives

my @final_call_vulnerable_keys=('xss','sql','exec','shell','fopen','eval'); # + upload
## filtered_groups array is used for merging between namespaces
my @filtered_groups=('xss','sql','exec','shell','sql_filtered','sql_num_checked','sql_num_filtered','array_checked','universal_checked','universal_filtered');

my @php_predefined_constants=('PHP_VERSION','PHP_MAJOR_VERSION', 'PHP_MINOR_VERSION', 'PHP_RELEASE_VERSION', 'PHP_VERSION_ID',
'PHP_EXTRA_VERSION', 'PHP_ZTS', 'PHP_DEBUG', 'PHP_MAXPATHLEN', 'PHP_OS', 'PHP_SAPI', 'PHP_EOL', 'PHP_INT_MAX', 'PHP_INT_SIZE', 'DEFAULT_INCLUDE_PATH', 'PEAR_INSTALL_DIR', 'PEAR_EXTENSION_DIR', 'PHP_EXTENSION_DIR', 'PHP_PREFIX', 'PHP_BINDIR', 'PHP_BINARY', 'PHP_MANDIR', 'PHP_LIBDIR', 'PHP_DATADIR', 'PHP_SYSCONFDIR', 'PHP_LOCALSTATEDIR', 'PHP_CONFIG_FILE_PATH', 'PHP_CONFIG_FILE_SCAN_DIR', 'PHP_SHLIB_SUFFIX','E_ERROR', 'E_WARNING', 'E_PARSE', 'E_NOTICE', 'E_CORE_ERROR', 'E_CORE_WARNING', 'E_COMPILE_ERROR', 'E_COMPILE_WARNING', 'E_USER_ERROR', 'E_USER_WARNING', 'E_USER_NOTICE', 'E_DEPRECATED', 'E_USER_DEPRECATED', 'E_ALL', 'E_STRICT', '__COMPILER_HALT_OFFSET__', 'TRUE',
'FALSE', 'NULL','true','false','null','__CLASS__', '__DIR__', '__FILE__', '__FUNCTION__', '__LINE__', '__METHOD__', '__NAMESPACE__', '__TRAIT__');
my @php_builtins=('__halt_compiler', 'abstract', 'and', 'array', 'as', 'break', 'callable', 'case', 'catch', 'class', 'clone', 'const', 'continue', 'declare', 'default', 'die', 'do', 'echo', 'else', 'elseif', 'empty', 'enddeclare', 'endfor', 'endforeach', 'endif', 'endswitch', 'endwhile', 'eval', 'exit', 'extends', 'final', 'for', 'foreach', 'function', 'global', 'goto', 'if', 'implements', 'include', 'include_once', 'instanceof', 'insteadof', 'interface', 'isset', 'list', 'namespace', 'new', 'or', 'print', 'private', 'protected', 'public', 'require', 'require_once', 'return', 'static', 'switch', 'throw', 'trait', 'try', 'unset', 'use', 'var', 'while', 'xor');
my @php_funcion_like_language_constructs=('return','require','require_once','print','include_once','include','echo','die','exit','eval','global'); ## this list is used to replace parenthesis-less calls to ones with parenthesis to simplify the parsing process (these are functions (or rather 'procedures') from our point of view)
## among all those language constructs, there are few that work as functions but are not functions
## Bellow hash contains relations between final_call_vulnerable keys (vulnerable calls) and corresponing groups of functions that can secure them along with the certainty rate (with higher value meaning most secure))
my %final_secure_keys_relation=();
$final_secure_keys_relation{'xss'}={'xss'=>4};
$final_secure_keys_relation{'sql'}={'sql_num_filtered'=>4,'sql_filtered'=>4,'sql_num_checked'=>4,'universal_checked'=>1,'universal_filtered'=>1,'array_checked'=>4};
$final_secure_keys_relation{'exec'}={'file_exists_checked'=>1,'array_checked'=>4,'universal_checked'=>1,'universal_filtered'=>1};
$final_secure_keys_relation{'shell'}={'shell'=>1,'array_checked'=>4,'universal_checked'=>1,'universal_filtered'=>1};
$final_secure_keys_relation{'fopen'}={'array_checked'=>4,'universal_checked'=>1,'universal_filtered'=>1};
$final_secure_keys_relation{'eval'}={'array_checked'=>4,'universal_checked'=>1,'universal_filtered'=>1};

# [DATA TRACKING VARIABLES]
# namespace
my @tracked_superglobals=('\$_GET', '\$_POST', '\$_COOKIE', '\$_SERVER', '\$_REQUEST', '\$_FILES', '\$HTTP_COOKIE_VARS', '\$HTTP_SERVER_VARS', '\$HTTP_RAW_POST_DATA', '\$HTTP_ENV_VARS', '\$_SESSION', '\$HTTP_SESSION_VARS', '\$HTTP_POST_FILES', '\$HTTP_POST_VARS', '\$HTTP_GET_VARS'); # \$_SESSION, some SERVER VARS for http headers, on which user can influent
### 'USER_AGENT', 'REQUEST_URI', 'QUERY_STRING''HTTP_ACCEPT' 'HTTP_ACCEPT_CHARSET' 'HTTP_ACCEPT_ENCODING' 'HTTP_ACCEPT_LANGUAGE'
my @durabilities=('volatile','permanent');

# add old HTTP_ superglobals
## we explicitly set list of vulnerable $_SERVER variables to avoid false positives from some of them
my @tracked_variables; ## global superglobals deriviations (variables pregs are kept here)
my @tracked_local_variables; # temporary list of local variables tracked in current function code block, POINTS to the ALL local variable pregs present in CURRENT function block, the original array is held in $registered_functions{'fname'} hash.
### for example:
## function f1($a) { } $b=f1(4);
## registered_variables{'f1::$a1'}=
my %registered_variables; ## shared namespace for registered variable names (NOT PREGS) (globals and locals, locals are prefixed with class::method_ names) 
my %registered_variables_trace;
my %registered_functions;	## hash of registered functions/classes (now only functions), key is function_name[::class_name[::function_name[...]]], it contains their arguments specification and type(class/function), nothing else (namespace is held in the $registered_variables hash, with prefixed (resolved :D) function names)
my %registered_constants; ## self-explainatory
# trace stacks (call, define)
my @call_trace; # call stack of recurrent call on each expression matching to function call, helps in right function calls interpretation
my @function_define_trace; ## array of nested defined function AND class names, cause from the namespace point of view function and class are the same thing
my $open_brackets_counter=0;
my $nested_expressions=0;
my $multi_line_comment=0;
## modes of line tracking
my $curr_line_tracked=0; ## 0 for no tracking, 1 for tainted value, 2 for local function variable, 3 for both (this should be the tracking status of the first met variable in current line)
use constant NOT_TRACKED=>0;
use constant TAINTED_VAL=>1;
use constant LOCAL_VAL=>2;
use constant SUPERGLOBAL=>3;
my $nested_includes=0;
my $max_string_length=60000;
my $sensitivity='positive'; ## change to 'negative' if you wan't to avoid some false positives, also risking some false negatives
my $expression_line;
my $pre_operator; ## whether or not left side of expression is appended
my $file; # 
my $line; ## parser-adjusted line content
my $line_copy; ## original line content
my $line_number; ## line number per file
my $is_tainted=0; ## curr call param value type tracker (1 for TAINTED, 2 for register_globals conditional on)
my $global_line_number=0; ## overall, logical line number when using multiple files
my $curr_local_line_number;
my $curr_local_virtual_line_number; ##
my @local_line_number; # line_number in current namespace
my @local_virtual_line_number; ## virtual line number for lines genereted by de-obfuscating mechanism and functions calling system to keep track on events (calls) sequence
my @called_functions; ## just a list of called function names, not used in data tracking
my @tracked_files; ## also not used in tracking, just to easily display list in the report
my $work_dir; ## current working directory
my $project_dir; ## this is the main project dir (like /home/acid/src/Perl/SCARY/victims/astguiclient-2.0.5/, this is apps' DocumentRoot
my $f;		## currently analysed file
my $project_name; ## (this is the last dir from project dir), therefore astguiclient-2.0.5
my $bugs='';
my $warnings='';
my $last_trace_append='';
my $sca_mode='sca'; ### auto_sca for whole project directories, sca for single files
my $prev_called_function='';
my @parser_active=(0); ## this is set to 0 or to 1, depending on the <?php or ?> metting

# with no is_int, is_uploaded_file (why?)
my %secured; # this hash holds separately sanitizing history records for all variables (or not ;D)
my %final_call_vulnerable;   ## and this one is its opposite
## add  (\w+::|\$\w+->) prefix to support object code
#my $function_call_preg='\s*([A-Za-z]+\w*)\s*(\(([^;]*)\))'; # latest (03.10.2012)
my $function_call_preg='\s*([A-Za-z]+\w*)\s*(\(([^;]*)\)?)'; # next one (parenthesis at the end is optional, so semicolons in params can be tolerated
my $function_def_preg='function\s+(\w+)\s*\(\s*(.*?)\s*\)\s*';
my $function_dec_preg="$function_def_preg;";
my $variable_preg='((\$\w+)(\[.*?\](\[.*?\])?)?)\s*';
my $assignment_preg='^'.$variable_preg.'([\.\+\*-\/]?)\s*=([^;]*)';
sub logme 
{
	my $outline = shift;
	if($outline=~/^\[((XSS)|(SQL)|(RFI)|(LFI)|(EXEC)|(EVAL)|(SHELL)|(FOPEN)|(UPLOAD))/)
	{
			if($outline=~/-TENTATIVE/)
			{
				print color 'bold green';
			}
			else
			{
				print color 'bold red';
			}
			$bugs.="$outline\n";
	}
	if($outline=~/^\[WARNING\]/)
	{
			print color 'bold yellow';
			$warnings.="$outline\n";
	}
	print color 'bold green' if($outline=~/^\[CALL|REGISTER|INCLUDE\]/);
	#print color 'bold white' if($outline=~/^\[DEBUG|MATCH\]/);
	print "$outline\n";
	print color 'reset';
}
sub print_variables 
{
	my $label=shift;
	&logme($label);
	foreach my $key(keys %registered_variables) {
		&logme("$key=>".$registered_variables{$key});
	}
}
sub print_constants 
{
	my $label=shift;
	&logme($label);
	while((my $key, my $val)=each(%registered_constants)) {
		&logme("$key=>$val");
	}
}
sub count_instances
{
	my $code=shift;
	my $str=shift;
	my $tmp_code=$code;
	my $indx=0;
	#print "[DEBUG COUNTER SINGLE QUOTES] code:$code, str:$str\n\n\n\n";
	while(index($tmp_code,$str)>0) { $tmp_code=~s/$str//; $indx++; }
	#print "[DEBUG COUNTER FINISHED $indx\n";
	return $indx;
}
sub in_array 
{
	my $seed=shift;
	my @arr=split(/\s/,shift);
	foreach my $row(@arr) 
	{
		 return 1 if($row eq $seed);
	}
	return 0;
}
sub remove_from_arr 
{
	my $var=shift;
	my @arr=split(/ /,shift);
	my @ret_arr=();
	foreach my $curr_var(@arr)
	{
		next if($curr_var eq $var);
		push(@ret_arr,$curr_var);
	}
	return @ret_arr;
}
## CODE TRACKING METHODS
sub include_exists 
{
 	my $search_for=shift;
 	foreach my $fname(@tracked_files) {
 		&logme("[INCLUDE MECHANISM] - checking whether $fname is included") if($debug_config{'INCLUDE'});
		return 1 if($fname eq $search_for);
 	}
 	return 0;
}
### patterns escaping (we need to generate PCRE patterns from variable names to track them)
sub escape_varname_to_regex 
{
	my $varname=shift;
	$varname=~s/\$/\\\$/g;
	$varname=~s/\[/\\\[/g;
	$varname=~s/\]/\\\]/g;
	return $varname;
}
sub descape_varname_from_regex 
{
	my $varname=shift;
	$varname=~s/\\\$/\$/g;
	$varname=~s/\\\[/\[/g;
	$varname=~s/\\\]/\]/g;
	return $varname;
}
sub get_curr_func_name 
{
	#print "[GET CURR FUNC NAME]\n";
	if(scalar(@function_define_trace) eq 0)
	{
		#print "NOTHING\n";
		return '';
	}
	#print "NAME:".$function_define_trace[scalar(@function_define_trace)-1]."\n";
	return $function_define_trace[scalar(@function_define_trace)-1];
}
sub varname_addr2preg 
{
	my $addr=shift;
	my @parts=split(/::/,$addr);
	return $addr if(scalar(@parts) eq 0);
	return &escape_varname_to_regex($parts[scalar(@parts)-1]);
}
sub resolve_full_variable_namespace_path 
{
	my $varname=shift;
	my $prefix=join('::',@function_define_trace);
	$prefix.='::' if(scalar(@function_define_trace));
	foreach my $tracked_variable(@tracked_superglobals)
	{ 	
		next if(!$tracked_variable);
		if($varname=~/^$tracked_variable/)
		{
			$prefix=''; 
			last;
		}
	}
 	$prefix='' if(&in_array($varname,"$registered_functions{$prefix}{'globals'}")); ## globals support (not tested) 
	return $prefix.$varname;
}
# secure_var($bug_group,$durability,$mapped_from_varaddr,$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline)
sub secure_var ## this is to set that value's been secured
{
	my $bug_group=shift;
	my $durability=shift; ## volatile|permanent
	my $mapped_from_varaddr=shift;
	my $mapped_from_vline=shift;
	my $mapped_to_varaddr=shift;
	my $mapped_to_vline=shift;
	my $secure_string="$mapped_from_vline"; 
	$secure_string="$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline" if($mapped_from_varaddr ne undef&&$mapped_to_vline ne undef);
	$secured{$bug_group}{$mapped_from_varaddr}{$durability}=() if($secured{$bug_group}{$mapped_from_varaddr}{$durability} eq undef);
	foreach my $s(@{$secured{$bug_group}{$mapped_from_varaddr}{$durability}})
	{
		return if($s eq $secure_string); # avoid duplicates
	}
	push(@{$secured{$bug_group}{$mapped_from_varaddr}{$durability}},$secure_string);
	#&logme("SECURE secured{{$bug_group}{$mapped_from_varaddr}{$durability}}$secure_string"); ##
}
sub trace_variable
{
			my $var=shift;
			my $resolved_var=&resolve_full_variable_namespace_path($var);
			$registered_variables_trace{$resolved_var}='' if($registered_variables_trace{$resolved_var} eq undef);
			$registered_variables_trace{$resolved_var}=$registered_variables_trace{$resolved_var}."$file:$line_number:$line_copy\n" if($last_trace_append ne "$file:$line_number:$line_copy\n");
			$last_trace_append="$file:$line_number:$line_copy\n";
			#print "[TRACE] $var:\n".$registered_variables_trace{$resolved_var};
}
sub set_curr_line_tracked
{
	#print "[DEBUG][SET_CURR_LINE_TRACKED CALLED], tracked_local_variables: @tracked_local_variables\n";
	my $line=shift;
	my $var_pattern;
	## higher prior for TAINTED_VAL (one $line can contain multiple variables and often it does, so tainted are preferred ones in identification)
	foreach $var_pattern(@tracked_superglobals)
	{
		last if(!$var_pattern);
 		if($line=~/$var_pattern/)
 		{	
			&logme("[MATCHING][".&descape_varname_from_regex($var_pattern)."]$file:$line_number:$line") if($debug_config{'MATCH'});
			return TAINTED_VAL;
		}
	}
	foreach $var_pattern(@tracked_variables)
	{
		last if(!$var_pattern);
 		if($line=~/$var_pattern\b/)
 		{	
			&logme("[MATCHING][".&descape_varname_from_regex($var_pattern)."]$file:$line_number:$line") if($debug_config{'MATCH'});
			return TAINTED_VAL;
		}
	}	
	if($line=~/$variable_preg/)
	{
		# if the variable is global (currently we don't care if it's initialized or not, as we do with other tainted vals (no ifs support and 'positive' approach)
		return TAINTED_VAL if(scalar(@function_define_trace) eq 0); ### however some value check would be appreciated, we have to store information if the empty value was set by default or not
		return LOCAL_VAL; # otherwise it's local, we are within a function/method definition block
	}
	return NOT_TRACKED;
	
	#foreach $var_pattern(@tracked_local_variables)
	#{
	#	last if(!$var_pattern);
 	#	if($line=~/$var_pattern/) 
 	#	{
	#		&logme("[MATCHING][".&descape_varname_from_regex($var_pattern)."]$file:$line_number:$line") if($debug_config{'MATCH'});
	#		return LOCAL_VAL;	
	#	}
	#}
	#return LOCAL_VAL;
}

## THIS METHOD REGISTERS NEW VARIABLE (SO IT SHOULD BE CALLED ONLY ONCE WHILE THE VALUE IS MET IN THE CODE)
sub register_variable 
{
#### ADD $curr_line_tracked modification (no modification, but rather use curr_variable_tracked instead of curr_line_tracked)
		my $varname=shift;
		my $val=shift;
		my $curr_var_tracked=&set_curr_line_tracked($varname);
		#print "[REGISTER DEBUG] $varname\n";
		my $tracked='regular';
		$tracked='local' if($curr_var_tracked==LOCAL_VAL);
		my $new='';
		my $resolved_varname=$varname;
		$resolved_varname=&resolve_full_variable_namespace_path($varname); ## prepend namespace prefix if var is not global
		## ADD GLOBALS SUPPORT TO RESOLVER
		$val=$resolved_varname if($varname eq $val); ## this is for proper function returns working
		my $variable_is_new=!&variable_exists($resolved_varname);
		## tracking helpers:
		## curr_line_tracked is an initial variable group identification, it can change here (for example $local="what".$local_ever.$TAINTED;)
		## based on the right side identification
		my $right_side_tracked=&set_curr_line_tracked($val); ## this should be always set to some positive value unless there's pure constant value
		&trace_variable($varname); # if($right_side_tracked);
		my $varname_preg=&escape_varname_to_regex($varname);		
		if($variable_is_new)
		{
			## when matching, we cut off namespace prefix
			switch($curr_var_tracked)
			{
				## right side tracked should be also examined in this place?
				case LOCAL_VAL
				{
					$tracked='local';
					if(!&in_array($varname_preg,"@tracked_local_variables"))
					{
						#print "Pushing $varname_preg to locals\n";
						push(@tracked_local_variables,$varname_preg); 
					}
				}
				case TAINTED_VAL
				{
					$tracked='tracked';
					 if(!&in_array($varname_preg,"@tracked_variables"))
					 {
					 	#print "Pushing $varname_preg to trackeds\n";
					 	push(@tracked_variables,$varname_preg); 
					 }
				} 
				## no other situation can occur
			} # switch
			$new='new ';
		} 
		## comment this out to fix that fucking test
		if($sensitivity eq 'negative' &in_array($varname_preg,"@tracked_variables")&&$right_side_tracked!=TAINTED_VAL&&$pre_operator eq '') 
		{
				#&logme("$varname REMOVED FROM tracked variables! ($val assigned)");
				@tracked_variables=&remove_from_arr($varname_preg,"@tracked_variables");
		}		
		#		## we remove from locals only if variable went into tainted group, independently from the pre_operator val
		if(&in_array($varname_preg,"@tracked_local_variables")&&$right_side_tracked==TAINTED_VAL) #&&$pre_operator eq ''
		{
			 #&logme("$varname MOVED FROM local variables to tracked variables ($val assigned)");
		  	 @tracked_local_variables=&remove_from_arr($varname_preg,"@tracked_local_variables");
			 $tracked='tracked';
			 push(@tracked_variables,$varname_preg) if(!&in_array($varname_preg,"@tracked_variables")); ## we have to remove those when function block ends, this will affect other functions, some false positives will rise from this
		}						
		#print "[RIGHT SIDE TRACKED: $right_side_tracked, pre_operator: $pre_operator\n";
		###HISTORY MERGE GOES HERE (it doesn't matter if variable is new)
		## secured{$vuln}{$resolved_varname} has to be, depending on the $val:
		## - overwritten (if val equals to another variable or derivate, with preferring of least-secured history when multiple variables detected) [DONE]
		## - erased, if $val is a constant	(CURRENTLY NOT IMPLEMENTED - SHOULD BE ERASED THE SAME WAY)
		## - ignored, if val is a function call (it's handled in other code section)
		## previously there was also $pre_operator eq '' condition, now it's been removed
		# if there is an overwrite or append with value that is not secured within current namespace, it has to be merged here
		# only current namespace lines are in our field of interest	
		my $trace_merge_done=0;
		if($right_side_tracked) ## get variable name to overwrite history with, only with rewrite!
		{
			foreach my $bug_group(@filtered_groups)
			{	
				while($val=~/$variable_preg/g)
				{
					my $right_varname=$1;
					$right_varname=&resolve_full_variable_namespace_path($right_varname);
					if($right_varname ne $resolved_varname&&$trace_merge_done eq 0)
					{
						#print "Going to append $resolved_varname trace with $right_varname trace.\n";
						$registered_variables_trace{$varname}=$registered_variables_trace{$varname}.$registered_variables_trace{$right_varname} if($registered_variables_trace{$right_varname} ne undef);
						$trace_merge_done=1;
					}
					if($secured{$bug_group}{$right_varname} eq undef||$secured{$bug_group}{$right_varname}{'permanent'} eq undef)
					{
						# erase, if there is anything to erase
						if($secured{$bug_group}{$resolved_varname}{'permanent'} ne undef)
						{
							for(my $i=0;$i<scalar(@{$secured{$bug_group}{$resolved_varname}{'permanent'}});$i++)
							{
								my @secure_string_parts=split(',',@{$secured{$bug_group}{$resolved_varname}{'permanent'}}[$i]);
								$secure_string_parts[0].="-".$curr_local_virtual_line_number-1 if($secure_string_parts[0]<$curr_local_virtual_line_number); ### append end of secured range for that variable since it's been tainted again from this line 
								@{$secured{$bug_group}{$resolved_varname}{'permanent'}}[$i]=join(',',@secure_string_parts);
							}
						}
					}
				}
			}
		}
		&logme("[REGISTER] registered $new$tracked variable $resolved_varname=$val") if($debug_config{'REGISTER'});
		if($pre_operator)
		{
			switch($pre_operator)
			{
				case '-' { $registered_variables{$resolved_varname}-=$val; }
				case '.' { $registered_variables{$resolved_varname}.=$val;  }
				case '+'{ $registered_variables{$resolved_varname}+=$val; }
				case '/' 
				{ 
					$val=~s/^\s*//; $val=~s/\s*$//;
					if($val eq ''||$val eq 0)
					{
						 $registered_variables{$resolved_varname}=0;
					}
					else
					{ 
						$registered_variables{$resolved_varname}/=$val;
					} 
				}
				case '*' { $registered_variables{$resolved_varname}*=$val; } 
			}
		}
		else
		{
			$registered_variables{$resolved_varname}=$val; ## overwrite anyway
		}
		return 1;			
}
## gets prefixed local function variable names
sub variable_exists  
{
	my $search_for=shift;
	return 1 if $registered_variables{$search_for} ne undef;
	return 0;
}
## checks, whether function is defined by user (otherwise it's an unknown (for this script) PHP function)
sub user_defined_function_exists
{	
 	return 1 if($registered_functions{shift});
 	return 0;
}
# this is preg_replace with eval option vulnerability specific check function
# this shit won't work unless I fix once fucking more that FUCKING params splitting code
sub preg_replace_eval_vuln
{
	# this should return 0 on no flaw, 1 on eval and 2 on control hijacking (but now it's just true/false, so control hijack will be reported the same way as pcre eval)
	#my $param_index=shift; # if it's 0, we probably deal with control hijack, if it's one or three, it's eval vuln
	my $preg_replace_pcre=shift;
	my $preg_replace_replacement=shift;
	my $preg_replace_subject=shift;	
#	print "[PREG REPLACE EVAL VULN CHECKER] preg_replace_pcre:$preg_replace_pcre, preg_replace_replacement: $preg_replace_replacement, preg_replace_subject: $preg_replace_subject\n";
	return 0 if(!($preg_replace_pcre=~/e'$/)&&!($preg_replace_pcre=~/e"$/));
	#print "[PREG REPLACE EVAL VULN CHECKER] e flag detected, good\n";
	if($preg_replace_replacement=~/\$\d+/)
	{
	#	print "Backreference found in the replacement string, bingo!\n";
		return 1; 
	}
	#print "No backreference found, no flaw :(\n";
	return 0;
}
## files includer
sub analyse_file 
{
	$nested_includes++;
	$parser_active[$nested_includes]=0;
	if($nested_includes==$max_nested_includes)
	{
		&logme("[ERROR] max nested dives reached ($max_nested_includes), check either my or its code :D") if($debug_config{'ERROR'});
		return;
	}
	$file=shift;
	chomp($file);
	push(@tracked_files,$file);
	$registered_constants{'__FILE__'}=$file;
	&logme("Analysing $file") if($debug_config{'DEBUG'});
	$line_number=1;
	$curr_local_line_number=1;
	$curr_local_virtual_line_number=1;
	my $FILE;
	open($FILE,"<$file") or &logme("$file: no such file!");
	if($FILE eq undef) 
	{
			&logme("[WARNING]: cannot open file $file") if($debug_config{'WARNING'});
			return 0;
	}
	&logme("[INCLUDE] $file") if($debug_config{'INCLUDE'});
	my $line;
	my $matched;
	while($line=<$FILE>) 
	{
				$line='' if($line=~/^\s*#/); ## bash|perl style comment
				$line='' if($line=~/^\s*\/\//); ## C style comment
				while($line)
				{
					$line_copy=$line;
					chomp($line_copy);
					if($line=~/^(.+?);/)
					{
						$matched=$1;
						$line=substr $line,length($matched)+1,length($line); ## cutt it off
						&parse_line("$matched;",$file);
						my $line_clear=$line;
						$line_clear=~s/^\s*//;
						$line_clear=~s/\s*$//;
						$curr_local_virtual_line_number++ if(!$line_clear);
					}
					else
					{
						 &parse_line($line,$file);
						 $line='';
					}		
				}
				$line_number++;
				$curr_local_line_number++;
				$curr_local_virtual_line_number++;
				$global_line_number++;
	}
	$nested_includes--;
	pop(@parser_active);
	return $line_number;
}
## PHP dentures
sub dir_name 
{
	my $arg=shift;
	$arg=~s/^\.\///;
	$arg=~s/\.\.\///g;
	$arg=reverse $arg;
	if($arg=~/\//) 
	{
		$arg=~s/^.*?(?=\/)//; ## remove file name
	}
	else 
	{
		$arg=$project_dir;
	}
	return reverse $arg;
}

## PARSER
## Following two methods are the this toy's core: parse_line and parse_expression, which together create poor imitation of PHP parser
## parse_line removes comments and splits lines if multiple semicolons are found
## and determines whether current line should be tracked (when one of tracked variables appears; list is appended in the real time)
## rest of work (all syntax related stuff, function calls, assignments, expressions and so on) is done by recurrent parse_expression function. 

sub parse_line
{
	$line=shift;
	chomp($line);
	#$line_copy=$line;
	parser_activation:
	if($parser_active[$nested_includes])
	{
		if($line=~/\?>/)
		{
			$parser_active[$nested_includes]=0;
			$line=~s/\?>//;
			goto parser_activation;
		}
	}
	else
	{
		if($line=~/<\?(php)?/i)
		{
			$parser_active[$nested_includes]=1;
			$line=~s/<\?(php)?//i;
			goto parser_activation;
		}
	}
	return ''	if($parser_active[$nested_includes] eq 0);
	#&logme("[DEBUG] LINE PARSE FUNCTION CALL") if($debug_config{'CALL'});
	if($line=~/\*\/\s*$/) 
	{ ## detection of multi-line comment closing
		$multi_line_comment=0;
		$line=~s/^\s*\*\///; 
	}
	if($line=~/\s*\/\*/) 
	{ ## detection of multi-line comment opening
		$multi_line_comment=1;	# /* */
	}
	$line=~s/^\s*//;
	$line=~s/\s*$//;
	return '' if($line eq ''||$multi_line_comment);
	## 
	my $file=shift;
	chomp($file);
	my $line_number=shift;
 	### Here are all fucking 'language constructs' that acting like functions called without parenthesis, we replace them to parenthesis form, as they should be  
	# remember to use $line_copy in the original report instead of $code
	my $fucked_construct=join("|",@php_funcion_like_language_constructs);
	my $check_preg='^('.$fucked_construct.')\s+[^\(]';
	my $fix_preg='^('.$fucked_construct.')\s+';
   if($line=~/$check_preg/)
   {
   	$line=~s/$fix_preg/$1\(/;
   	$line=~s/;$/\);/;
   }
	# backtick support
	$line=~s/(?=(\.\s*)?)`(.*?\$+.*?)`(?=\s*(\.|;))/shell_exec("$2")/g;
	#	$line=~s/\(int\)/int\( how to catch the thing after cast operator, I mean a variable
	## now we have to keep tracked_locals properly initialized
	@tracked_local_variables=();
	@tracked_local_variables=@{$registered_functions{&get_curr_func_name()}{'params_simple'}} if(&get_curr_func_name() ne '');
	$curr_line_tracked=&set_curr_line_tracked($line);
	$expression_line=$line;
 	&parse_expression($line);
} ## sub

## this method is intended to pull out only resolved variable names from the returned, parsed expression, to be used for returns values merging into secured history
## however, if there are constants, we don't return them unless there's nothing more than them (we prefer to return variables)
sub cut_vars
{
	my $string=shift;
	my @variables=();
	my $const_val;
	# first, pull out all variable pregs
	my $preg="(\\w+::)*$variable_preg";
	while($string=~/($preg)/g)
	{
		push(@variables,$1); ## this is fucked (no prefix returned)
	}
	return join(',',@variables) if(scalar(@variables)>0);
	# then pull out all constant pregs, if there are no variable pregs
	while($string=~/$function_call_preg/g)
	{
		my $params=$1;
		$string=$1; ## cut the fuck off the rest
	}
	return $string; ## not tested ;D
}
## parse_expression DESCRIPTION
## detects function calls, constants and variables definition expressions
## 1. THERE HAVE BEEN DISTINGUISHED THREE GROUPS OF EXPRESSIONS: function calls, assignments and concatenations (expression evaluations)
## 2. resolved/evaluated expression value is returned as a string (for instance constants usage, like DATADIR."/file.php" when DATADIR is a constant
## every single type can recursively call another instance of this method which can operate again on any of those types
## parse_expression returns one of the following:
## ASSIGNMENTS -> returnsn right side evaluation
## EVALUATION -> resolved/concatenated value (code, constans or their mix)
## FUNCTION CALL -> returns code itself
## AFTER EACH CALL CURRENTLY PROCESSED PARTS ARE CUT OFF, ONE AFTER ANOTHER, SEQUENTIALLY 
sub parse_expression 
{
#	sleep(1);
	$nested_expressions++;
	my $code=shift;
	my $code_original=$code;
	#print "[EXPRESSION ($nested_expressions)] $code\n" if($debug_config{'EXPRESSION'});
	#while($code=~/^\s*\(.*\)\s*$/) 
	#{ 
	#	$code=~s/^\s*\(\s*//; ## get rid of optional parenthesis smothering expression
	#	$code=~s/\s*\)\s*$//;
	#}
	# remove
	# spaces and other shit
	$code=~s/^\s*//;
	$code=~s/\s*$//;
	$code=~s/^;*$//; ## remove white characters and semicolons left from parent-call after subst, probably we'll rewrite it later anyway (added ^ dash at 15.11.2012 to learn it to catch interface definitions
	$code=~s/^\.?//g; ## optional concatenation dot (remember to check how assignment value supports concatenation to avoid collision
	$code=~s/^\s*//;
	$code=~s/\s*$//;
	if(!$code) { $nested_expressions--; return '';} ## return empty on empty
	if($nested_expressions==$max_nested_expressions)
	{
		&logme("[ERROR] Max nested calls limit ($max_nested_expressions) reached, exiting.") if($debug_config{'ERROR'});
		return;
	}
	my 	$left_side=shift;
	my $last_resolved_path;
	#&logme("[EXPRESSION] code:$code\n[EXPRESSION] left_side:$left_side"); 	
	my $return_met=0;
	if($code=~/^\s*return\s*/&&scalar(@function_define_trace)>0) 
	{
		$code=~s/^\s*return\s*//;
		if($code=~/^\s*\(/)
		{
			$code=~s/^\s*\(\s*//;
			$code=~s/\s*\)\s*$//;
		}
		$return_met=1;
	}
	$left_side=&resolve_full_variable_namespace_path($left_side) if($left_side=~/^\$/); ## otherwise (if doesn't match to ^\$, it should be error reported and erased)

	## if there's been made an assignment to the currently tracked left side variable, we know, to which one
	## left side registration
	## HOW DOES PARSE EXPRESSION WORK
	## we always do return $comma.$return_expr.&parse_expression($postmatch);
	## where $comma is a comma or empty value, $return_expr is resolved expression for the first current entity match, postmatch is what's left after first current match removal
	my $return_expr=''; 
	my $comma='';
	## comma handling:
	if($code=~/^,/) { $comma=','; $code=~s/^,//;} ## we'll have to make it more elegant, this sucks a bit (there's a chance that this line can be removed ;D)
	## IF/WHILE/FOR/SWITCH STATEMENTS NOT IMPLEMENTED
	
	## FUNCTIONS DEFINITIONS DETECTION (FUNCTIONS REGISTRATION)
	if($code=~/$function_def_preg/)
	{
		my $declaration_only=0; # introduction to tolerate interfaces (object code)
		my $def_operation='DEFINITION';
		if($code=~/$function_dec_preg/)
		{
			$def_operation='DECLARATION';
			$declaration_only=1; 
		}
		$curr_line_tracked=LOCAL_VAL; ## set kind of tracking line (loca variables in functions)
		my $f_name=$1;
		my $f_params=$2;
		&logme("[FUNCTION $def_operation] $f_name detected") if($debug_config{'FUNCTION_DEFINITION'});
		my @f_params_arr=split(/\s*,\s*/,$f_params);
		my @f_params_complete=(); ## this array is also used for in-function definition params tracking, so we can attribute it later when real tracked variable is passed to this function through this parameter
		my @f_params_simple_tracked=();
		my @globals=();
		my @return_points=();
		my $var_name;
		my $is_referenced;
		$f_name=&resolve_full_variable_namespace_path($f_name);
		if(!$declaration_only)
		{
			push(@function_define_trace,$f_name);
			push(@local_virtual_line_number,$curr_local_virtual_line_number);
			push(@local_line_number,$curr_local_line_number);
			$curr_local_virtual_line_number=$curr_local_line_number=1;
		}
		foreach my $f_param_arr_single(@f_params_arr)
		{
			$is_referenced=0;
			$var_name='';
			my $default_value;
			if($f_param_arr_single=~/&?(\$\w+)(\s*=\s*(\w+))?/) ## default value possible
			{
				$var_name=$1;
				$is_referenced=1 if($f_param_arr_single=~/&/);
				$default_value=$3;
				$default_value='' if($default_value eq undef);
				push(@f_params_simple_tracked,&escape_varname_to_regex($var_name));
				push(@f_params_complete,{'var_name'=>$var_name,'reference'=>$is_referenced,'preg'=>&escape_varname_to_regex($var_name)});
				&logme("[FUNCTION DEFINITION] $file:$line_number - $f_name:&get_curr_func_name()}{'name'} $f_param_arr_single parameter ($var_name) is referenced: $is_referenced") if($debug_config{'FUNCTION_DEFINITION'});
				&register_variable($var_name,$default_value);
			}
			else
			{
				&logme("[PARSE ERROR] in function definition $f_name, param: $f_param_arr_single does not look like a variable!") if($debug_config{'ERROR'});
			}
		}
		if(!&user_defined_function_exists($f_name))
		{
			$registered_functions{$f_name}{'file'}=$file;
			$registered_functions{$f_name}{'name'}=$f_name;
			$registered_functions{$f_name}{'open_brackets'}=$open_brackets_counter;
			$registered_functions{$f_name}{'params'}=\@f_params_complete;
			$registered_functions{$f_name}{'params_simple'}=\@f_params_simple_tracked;
			$registered_functions{$f_name}{'class'}=0;
			$registered_functions{$f_name}{'lines_overall'}=0;
			$registered_functions{$f_name}{'defined_on_line'}=$line_number;
			$registered_functions{$f_name}{'returns'}=\@return_points;
			$registered_functions{$f_name}{'globals'}=\@globals;
			## return points contains expressions standing after return with resolved variable and function names
			## they have to be resolved
		}
		if($declaration_only)
		{
			$code=~s/$function_dec_preg//;
		}
		else
		{
			$code=~s/$function_def_preg//;
		}
		$return_expr=$comma.&parse_expression($code,$left_side); 
		$nested_expressions--; 
		return $return_expr;
	}
	## BRACKETS
	if($code=~/^\{/)
	{
		#&logme("[BRACKET OPEN: $code]");
		$code=substr $code,2,length($code);
		$open_brackets_counter++;
		$return_expr=$comma.&parse_expression($code,$left_side); 
		$nested_expressions--;
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met);
		return $return_expr;
	}
	if($code=~/^}/)
	{
	#	&logme("[BRACKET CLOSE: $code]");
		$code=substr $code,2,length($code);
		$open_brackets_counter--;
		## clearing function-definition stack,flush tracked_local_variables pregs and declare stack
		if($open_brackets_counter eq $registered_functions{&get_curr_func_name()}{'open_brackets'})
		{
			@tracked_local_variables=() if(&get_curr_func_name());
			#&logme("[FUNCTION PARSER] - CLOSING ".$registered_functions{&get_curr_func_name()}{'name'});
			$registered_functions{&get_curr_func_name()}{'lines_overall'}=>$line_number-$registered_functions{&get_curr_func_name()}{'defined_on_line'};
			pop(@function_define_trace);
			my $last_curr_virtual_line_number=pop(@local_virtual_line_number);
			my $last_curr_local_line_number=pop(@local_line_number);
			$curr_local_virtual_line_number=$local_virtual_line_number[scalar(@local_virtual_line_number)-1]+$last_curr_virtual_line_number;
			$curr_local_line_number=$local_line_number[scalar(@local_line_number)-1]+$last_curr_local_line_number;
			$curr_line_tracked=LOCAL_VAL if(scalar(@function_define_trace));
		}
		$return_expr=$comma.&parse_expression($code,$left_side);
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
		$nested_expressions--;
		return $return_expr;
	}
	
	## ASSIGNMENTS
	if($code=~/$assignment_preg/)
 	{
 		my $match=$&;
 		#&logme("[DEBUG] ASSIGNMENT detected") if($debug_config{'EXPRESSION'});
 		my $var_name=$1;
 		$pre_operator=$5;
 		my $right_side=&parse_expression($6,$var_name); 
		#print "CALLING REG VAR $var_name$pre_operator=$right_side\n";
 		&register_variable($var_name,$right_side);
		
		## recursively we identify right side's classification (calls/evaluations)
		## second argument is the LEFT side, because we have to also know WHERE DOES THE RESULT GO FINALLY
 		$nested_expressions--;
 		&logme("[DEBUG] ASSIGNMENT $var_name=$right_side") if($debug_config{'EXPRESSION'});
		$code=substr $code, length($match)+1,length($code);  ## wyciecie macza
 		$return_expr="$comma$var_name=$right_side".&parse_expression($code,$left_side);
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met);  		 
 		$nested_expressions--; 
 		return $return_expr;
 	}
 	## 2 FUNCTION CALLS
 	# function_call_detection_section:
 	if($code=~/^$function_call_preg/)	### IT'S A FUNCTION CALL
	{		
			## with non bracket calls support constant expressions started to get here too
			#print "HOW THE FUCK $code is an f call?\n";
			my $match=$&; ## HERE'S THE WHOLE INTERNAL EXPRESSION (THE FUCKING THING BETWEEN THE PARENTHESIS)
			my $called_function;
			if($registered_functions{&resolve_full_variable_namespace_path($1)})
			{
				$called_function=&resolve_full_variable_namespace_path($1);	
			}
			else
			{
				$called_function=$1;
			}
			## end of checkups
			#&logme("[CALL] $1 (preg:$function_call_preg)detected (curr_line_tracked:$curr_line_tracked), left_side: $left_side") if($debug_config{'CALL'});				
			my $call_params=$2;
			
					
			my $call_params_matchoff=$2;
			my $call_params='';
			my $bracket_count=0;
			my $bracket_met=0;
			for(my $i=0;$i<length($call_params_matchoff);$i++) 
			{	
			 	my $char=substr ($call_params_matchoff,$i,1);
			 	if($char eq '(')
			 	{
			 		$bracket_met=1;
			 		$bracket_count++;
		 		}
			 	$bracket_count-- if($char eq ')');
			 	$call_params.=$char;
				if($bracket_met eq 1&&$bracket_count eq 0)
				{
						## the match is shortened by the length of what is left from the string after cutting out the matches from the parenthesis
						#print "[MATCH PRE DEBUG]: $match, call_params collected: $call_params\n";
						$match=substr $match,0,length($match)-(length($call_params_matchoff)-length($call_params)); 
						#print "[MATCH DEBUG] new match: $match\n";
						last;
				} 				
 			}
 			
			while($call_params=~/^\s*\(/) ## remove brackets if present
			{
				$call_params=~s/^\s*\(//;
				$call_params=~s/\)\s*$//;
			}
			$call_params=~s/\s*!\s*//g; ## remove white chars and negations
			$prev_called_function=$called_function;
			## ADD REFERENCE SUPPORT HERE - > THIS IMPACTS THE LEFT_SIDE BEHAVIOUR
			## for each iteration after commas separation we need to estimate curr_line_tracked state again
			#if($curr_line_tracked) ## also internal, not neccesarily GLOBAL TRACKED variable, we just track it, cause it comes from parameters and we wait to merge it
			#{
		 		push(@called_functions,$called_function) if(!&in_array($called_function,"@called_functions"));
		 		push(@call_trace,$called_function);
		 		&logme("[CALL-TRACED] function:$called_function, params: $call_params, left side: $left_side") if($debug_config{'CALL'});
		 		my @parsed_call_params=();
		 		my $nested_decompose_calls=0;
		 		decompose_call_params:
		 		$nested_decompose_calls++;
		 		goto params_decomposed if($nested_decompose_calls eq 50); ## temporary safety break, it fucks sometimes
		 		$call_params=~s/^\s*//;
		 		$call_params=~s/\s*$//;
				goto params_decomposed if($call_params eq '');
				## CALL #0		 		
		 		## if(is_dir("dir/$_GET['sth']",trim(ucfirst("somepath".$_GET['sth2']))))
		 		## call_params initial: is_dir("dir/$_GET['sth']",trim(ucfirst("somepath".$_GET['sth2'])))
		 		## prematch=''
		 		## match=is_dir("dir/$_GET['sth']",trim(ucfirst("somepath".$_GET['sth2'])))
		 		## @prematch_params=()
				## @parsed_call_params=() # after push
				## @parsed_call_params=(''); # after condition
				## 
				## 		CALL #1
				## 		
		 		## CALL #0-back
		 		## $parsed_call_params[0].=CALL #1 returned value
		 		my $param_match;
		 		my $param_prematch;
		 		if($call_params=~/$function_call_preg/)
		 		{
		 			#print "Another call detected.\n";
		 			$param_prematch=$`; 
		 			$param_match=$&; ## function call
		 			$param_prematch=&parse_expression($param_prematch,$left_side);
		 		}
		 		else
		 		{
		 			#print "HELLO HELLO $call_params\n";
		 			## a trick (parse it, so variables will be catched, but do not return it, since concatenation fucks up string removal
		 			$param_prematch=$call_params; 
		 			$last_resolved_path=&parse_expression($call_params,$left_side); ## this is for concatenation purposes (includer and so on), this variable is not used in this parameter parsing
		 			#print "RETURNED prematch: $param_prematch\n";
		 			$param_match='';
		 		}
		 		## if there are any commas, they have to be located in $prematch
		 		my @prematch_params=split(/\s*,\s*/,$param_prematch);
		 		push(@prematch_params,'') if($param_prematch=~/,$/); ## little split behavior fix :>
		 		#print "[COMPOSER DEBUG] curr prematch ($param_prematch) params count: ".scalar(@prematch_params).", contents: @prematch_params\n";
		 		if(scalar(@parsed_call_params) ne 0)
		 		{
		 			#print "[COMPOSER DEBUG] appending last parsed_call_params element (".$parsed_call_params[scalar(@parsed_call_params)-1].") with ".$prematch_params[0]."\n";
		 			$parsed_call_params[scalar(@parsed_call_params)-1].=$prematch_params[0];
		 			shift(@prematch_params);
					#print "[COMPOSER DEBUG] prematch params after shift: @prematch_params\n";
		 			## remove the first element
		 		}
		 		push(@parsed_call_params,(@prematch_params));
		 		#print "[COMPOSER DEBUG] parsed_call_params after push of @prematch_params: @parsed_call_params\n";
	 			push(@parsed_call_params,'') if(scalar(@parsed_call_params) eq 0);
	 			my $parsed_param_match=&parse_expression($param_match,$left_side);
	 			#print "[COMPOSER DEBUG] appending last element of parsed_call_params with $parsed_param_match\n"; 
	 			$parsed_call_params[scalar(@parsed_call_params)-1].=$parsed_param_match;
	 			## now, remove (substr) the prematch and match from $curr_call_params
	 			my $cutoff_index=1;
	 			$cutoff_index++ if($param_match ne ''&&$param_prematch ne '');
	 			#print "[COMPOSER DEBUG] going to remove $param_prematch$param_match from $call_params (prematch:$param_prematch,match:$param_match)\n";
	 			### OK, the only thing that is fucked is the index of cutoff
	 			$call_params=substr $call_params, length($param_match)+$cutoff_index+length($param_prematch),length($call_params);  ## match cutoff
	 			#print "[COMPOSER DEBUG] done, call_params after shortening: $call_params\n";
#	 			sleep(1);
	 			## ok, we should be done ;]
	 			$call_params=~s/^\s*//;
		 		$call_params=~s/\s*$//;
		 		goto decompose_call_params if($call_params ne ''); ## there is still work to do
		 		params_decomposed:
		 		#print "Params count: ".scalar(@parsed_call_params)."\n";
		 		#print "Params splitted: @parsed_call_params\n";
		 		
		 		my $tracked_param_found=0; ## for anomalies detection (if none of the parameters was tracked warning is raised)
		 		my $is_user_defined=0;
		 		my $param_index=-1;  ## for now it's fixed, for one parameter

		 		foreach my $curr_call_param(@parsed_call_params)
		 		{
		 			#print "Foreaching $curr_call_param, called function: $called_function\n(line_copy: $line_copy,\nline_number:$line_number, file:$file)\n";
		 			$param_index++; 
					my $params_tracked_variable='';
					my $params_tracked_variable_original='';
					my $passed_by_reference=0;
					my $received_as_reference=0;
					my $type_matched=0; ## this value will replace 'call_params_valuable', if 0, we deal with irrelevant parameter
					my $local_param_name=''; ## declared name of user-defined function parameter 
					my $i=0;
					#print "[DEBUG] call_params_separated: @call_params_separated, tracked_local_variables: @tracked_local_variables\n";
					foreach my $tracked_variable((@tracked_variables,@tracked_local_variables))
					{ 
						next if(!$tracked_variable);
						if($curr_call_param=~/($tracked_variable)/) ## \$_GET\['page'\]
						{
							$params_tracked_variable=$1;
							$tracked_param_found=1;
							if($i<scalar(@tracked_variables))
							{
								$type_matched=TAINTED_VAL;
							}
							else
							{
								$type_matched=LOCAL_VAL;
							}
							$params_tracked_variable_original=$params_tracked_variable;
							$params_tracked_variable=&resolve_full_variable_namespace_path($params_tracked_variable);
						#	&logme("[RESOLVER] params_tracked_variable: $params_tracked_variable");
							goto call_track_found;
						}
						$i++;
					}
					foreach my $tracked_variable(@tracked_superglobals)
					{ 	
						next if(!$tracked_variable);
						if($curr_call_param=~/($tracked_variable(\['?"?\w+'?"?\])*)/)
						{
							$params_tracked_variable=$1;
							$tracked_param_found=1;
							if($params_tracked_variable=~/^\$\w+$/) 
							{
								$type_matched=SUPERGLOBAL;
							}
							else
							{
								$type_matched=TAINTED_VAL;
							}
							goto call_track_found;
						}
					}					
					call_track_found:
				  	$is_tainted=0;
				  	$is_tainted=1 if($type_matched==TAINTED_VAL);		
				  	$passed_by_reference=1 if($`=='&');
				  	#print "CALLED FUNCTION: $called_function\n";
					if($registered_functions{$called_function} ne undef)	### user-defined function call detected
					{
						#&logme("USER-DEFINED FUNCTION $called_function CALL DETETCED!");
				  		if($type_matched eq SUPERGLOBAL)
				  		{
							  	&logme("[WARNING] - direct call to $1 superglobal found - sanitizing function?") if($debug_config{'WARNING'});
					  			## anomaly report and go further
					  			next;
				  		}
				  		## if it's not a local one, we prefix it, so we can use other information from its namespace		  		
						$is_user_defined=1;	
						my @params=@{$registered_functions{$called_function}{'params'}};
						if(scalar(@params)>0)
						{
				  			$local_param_name=$called_function.'::'.$params[$param_index]{'var_name'}; ## let's assume a number if function is not defined yet
				  			$received_as_reference=1 if($params[$param_index]{'reference'}); ## we have to remember to port this one when definition is discovered
				  			#print "Local param name: $local_param_name\n";
				  		}
				  		## sanitization and final calls history merge takes place here
				  		## $params_tracked_variable->$local_param_name
				  		## [READY]
				  		foreach my $filtered_group(@final_call_vulnerable_keys)
				  		{
							# This has sense only in one case: external variable is tainted and there is final call in internal param, to which external one is mapped
							# therefore we propagate tainted property from external into internal variable's value, therefore making it visible as a bug
							last if($local_param_name eq undef);
							last if($local_param_name=~/^\s*$/);
							my $final_call_vuln_curr_cnt=0;
							$final_call_vuln_curr_cnt=scalar(@{$final_call_vulnerable{$filtered_group}{$local_param_name}}) if($final_call_vulnerable{$filtered_group}{$local_param_name} ne undef);
				  			if($final_call_vulnerable{$filtered_group}{$local_param_name} ne undef)
				  			{ 
				  				for(my $i=0;$i<$final_call_vuln_curr_cnt;$i++)
				  				{
									my $code_trace=$registered_variables_trace{$params_tracked_variable}.$registered_variables_trace{$local_param_name};
									&set_final_call_vulnerable($filtered_group,$params_tracked_variable,$curr_local_virtual_line_number,$local_param_name,$final_call_vulnerable{$filtered_group}{$local_param_name}[$i]{'mapped_from_vline'},$final_call_vulnerable{$filtered_group}{$local_param_name}[$i]{'code'},$code_trace,$is_tainted,$final_call_vulnerable{$filtered_group}{$local_param_name}[$i]{'nullbyte'});
								}
				  			}
				  		}
				  		foreach my $filtered_group(@filtered_groups)
				  		{
							last if($local_param_name eq undef);
							last if($local_param_name=~/^\s*$/);		  			
				  			## secured history merge has to work in both directions (external->internal and internal->external), BUT
				  			## internal->external have to be temporary (unless it's a reference)
							### Ok, first we secure the external variable if the local params mapped is secured inside its function and it's passed as a reference
							foreach my $durability(@durabilities)
							{
								# first, internal->propagateTo(external) if reference
								if($secured{$filtered_group}{$local_param_name}{$durability} ne undef)
								{
											&secure_var($filtered_group,$durability,$params_tracked_variable,$curr_local_virtual_line_number,'','') if($received_as_reference);
											### Now we propagate the security history of variable mapped from the parameter into the local variable
											foreach my $secure_string(@{$secured{$filtered_group}{$local_param_name}{$durability}})
											{
												#secure_var($bug_group,$durability,$mapped_from_varaddr,$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline)
												my @secure_string_parts=split(',',$secure_string);
												my $mapped_to_vline=$secure_string_parts[0];
												&secure_var($filtered_group,$durability,$params_tracked_variable,$curr_local_virtual_line_number,$local_param_name,$mapped_to_vline);
											}
								}
								## this has to occur only once for function call and should be places outside this foreach, but I'm not feeling like rebuilding it right now ;D 
						  		if($param_index eq 0)
						  		{
						  			#&logme("ok, shall we merge in all returns with the left side here? (left side: $left_side)");
				  					#print $registered_functions{$called_function}{'returns'};
				  					foreach my $return_instance(@{$registered_functions{$called_function}{'returns'}})
				  					{
				  						$return_instance=~/(\d+):(.*)/;
				  						my ($return_internal_line,$returned_value)=($1,$2);
				  						#print "Return: $return_instance (checking for secured{$filtered_group}{$returned_value})\n"; ## instead of the simple string there has to be resolved local_param_name (it should be already afaik)
										## ok, for now it's just one return
										## this should not take place when returned_value is not an variable address
										next if($secured{$filtered_group}{$returned_value} eq undef);
										foreach my $secured_string((@{$secured{$filtered_group}{$returned_value}{'permanent'}},@{$secured{$filtered_group}{$returned_value}{'volatile'}}))
										{	
							#				print "$returned_value is secured from $filtered_group\n"; # I'm not sure this is currently supposed to work
											if($left_side ne '')
											{
												#secure_var($bug_group,$durability,$mapped_from_varaddr,$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline)
												&secure_var($filtered_group,'permanent',$left_side,$curr_local_virtual_line_number,'','');
											}
											else
											{
												&secure_var($filtered_group,'volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','');
											}
										}
						  			} ## end of foreach on returns
						  		}	 ## end of if param_index eq 0
						  	}	# end of durability foreach
						} # end of filtered group foreach
						#next;
				  	} ### user def
				  	else
					{
				  	## if we're here, we're dealing with unrecognized function call (probably PHP native)
				  		# first, natives moved here from the alternative (curr_line_tracked=0) block
				  	 		switch($called_function)
		 					{
		 						#case 'list'
		 						#{
		 						#	print "LIST CALL DETECTED on $curr_call_param\n";
		 						#}
		 						case 'dirname' 
								{							
									my $subst=&parse_expression($curr_call_param,$left_side);
									$subst=&dir_name($subst);
									$code=substr $code, length($match)+1,length($code);  ## match cutoff
									$return_expr=$comma.$subst.&parse_expression($code,$left_side); 
									push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met);
									$nested_expressions--;
									pop(@call_trace);
									return $return_expr;
								}
								case 'define' 
								{
									my $tmp;
									my $tmp2;
									$tmp=$curr_call_param;	
									if($tmp=~/(.*?),\s*(.*)/)
									{
										$tmp=$1;
										$tmp2=$2;
										$tmp=~s/^('|")//;
										$tmp=~s/("|')$//;
										$tmp2=&parse_expression($tmp2);
										&logme("[RESOLVED] $tmp->$tmp2") if($debug_config{'RESOLVE'});
										$registered_constants{$tmp}=$tmp2;
									}
								}
								case 'global' 
								{
									## globalization support (not tested as far as I know)
									if (&get_curr_func_name() ne ''&&$registered_functions{&get_curr_func_name()}{'globals'} ne undef)
									{
#										print $registered_functions{&get_curr_func_name()}{'globals'}."\n";
										push(@{$registered_functions{&get_curr_func_name()}{'globals'}},$1) if($curr_call_param=~/^$variable_preg/);
									}
								}
						}
					## FIRST, SECURE CALLS TRACING
					## IN THE FIRST PLACE, FLAW SPECIFIC 
					## [ XSS ]
						if(in_array($called_function,"@xss_filtering_functions"))
						{
							&secure_var('xss','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','')  if(in_array($called_function,"@xss_filtering_functions"));
							&secure_var('xss','permanent',$left_side,$curr_local_virtual_line_number,'','') if($left_side ne undef);
						}	
						## [SQL]	
						if(in_array($called_function,"@sql_filtering_functions")||in_array($called_function,"@sql_num_filtering_functions")||in_array($called_function,"@sql_num_checking_functions"))
						{
							## UGLY FALSE POSITIVE WITH ADDSLASHES functions class and concatenation with single quotes - workaround
							## add condition here (whether left side of expression has even number of ' - count_instances($code,"'");
							my $params_tracked_variable_preg=&escape_varname_to_regex($params_tracked_variable_original);
							$expression_line=~/$params_tracked_variable_preg/;
							my $dynamic_left_side=$`.$registered_variables{$params_tracked_variable}; ## get variable's value
							#print "[DEBUG-DYNAMIC-LEFT-VALUE]: $dynamic_left_side\n";
							my $single_quotes_before=&count_instances($dynamic_left_side,"'");
							## end of slashes based false positive detector						
							&secure_var('sql_filtered','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','') if($single_quotes_before%2); 
							&secure_var('sql_num_filtered','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','') if(&in_array($called_function,"@sql_num_filtering_functions"));
							&secure_var('sql_num_checked','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','') if(&in_array($called_function,"@sql_num_checking_functions"));								
							if($left_side ne undef) ## if leftside is not undef it's almost always ELSE for the final call condition
							{
								### it should be SQL filtered here
								&secure_var('sql_filtered','permanent',$left_side,$curr_local_virtual_line_number,'','') if(&in_array($called_function,"@sql_filtering_functions")&&$single_quotes_before%2);
								&secure_var('sql_num_filtered','permanent',$left_side,$curr_local_virtual_line_number,'','')  if(&in_array($called_function,"@sql_num_filtering_functions"));
								&secure_var('sql_num_checked','permanent',$left_side,$curr_local_virtual_line_number,'','')  if(&in_array($called_function,"@sql_num_checking_functions"));
							}
						}	
						## [SHELL]
						if(in_array($called_function,"@escape_shell_functions"))
						{
								 &secure_var('shell','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','');
								 &secure_var('shell','permanent',$left_side,$curr_local_virtual_line_number,'','') if($left_side ne undef); ## if leftside is not undef it's almost always ELSE for the final call condition
						}
						## [EVAL], [FOPEN], [EXEC], - evals are filtered only by standard checking functions crap
						## [UPLOAD] - not implemented
						## ADDITIONALLY 'UNIVERSAL' CHECKS SECTION
						## Ok, question - shall it be volatile or permanent? It could depend on the sensibility setting, for now let's just set it as volatile
						&secure_var('array_checked','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','')  if(&in_array($called_function,"@array_functions"));
						if(&in_array($called_function,"@filtering_functions"))
						{
							if($called_function eq 'preg_replace'&&preg_replace_eval_vuln($parsed_call_params[0],$parsed_call_params[1],$parsed_call_params[3],$param_index))		### params required here
							{
								&set_final_call_vulnerable('eval',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted) 
							}
							else
							{
								&secure_var('universal_filtered','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','');
							}
						}
						&secure_var('universal_checked','volatile',$params_tracked_variable,$curr_local_virtual_line_number,'','') if(&in_array($called_function,"@checking_functions"));
						if($left_side ne undef)
						{
									&secure_var('universal_filtered','permanent',$left_side,$curr_local_virtual_line_number,'','') if(&in_array($called_function,"@filtering_functions")); ## left side does not interest us with preg_replace with e flag	
						}
						## FINAL CALLS TRACING (replaced 'code' with 'line copy')
						# set_final_call_vulnerable($bug_type,$var_addr,$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline,$code,$code_trace,$external_is_tainted)
						## [XSS]
						&set_final_call_vulnerable('xss',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted) if(&in_array($called_function,"@xss_vulnerable_functions")); 
			 			## [SQL]
						&set_final_call_vulnerable('sql',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted) if(&in_array($called_function,"@sql_vulnerable_functions")); #
			 			 my $nullbyte_required=1; 
						 $nullbyte_required=0 if($last_resolved_path=~/$variable_preg$/);					 
						 if(&in_array($called_function,"@exec_vulnerable_functions"))
			 			{
			 				## [INCLUDE/REQUIRE] (embedded here also local require system, since we changed behaviour of curr_line_tracked variable
			 				#print "[RESOLVE-INCLUDE] GOING TO RESOLVE $curr_call_param\n";			 				
			 				my $include_resolved_call_param=$last_resolved_path;
			 				while($curr_call_param=~	/$variable_preg/g)
			 				{
			 					my $value='';
			 					$value=$registered_variables{$1} if($registered_variables{$1} ne undef);
			 					$include_resolved_call_param=~s/$variable_preg/$value/;
			 				}
			 				&set_final_call_vulnerable('exec',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted,$nullbyte_required);
							&logme("[RESOLVED-INCLUDE] $include_resolved_call_param") if($debug_config{'RESOLVE'});
							if(-e $project_dir.'/'.$include_resolved_call_param)
							{	## we perform an include, there's a file present and resolved
								if(!&include_exists($project_dir.'/'.$include_resolved_call_param))
								{
									my $curr_file=$file;
									my $curr_line_number=$line_number;
									&analyse_file($project_dir.'/'.$include_resolved_call_param);
									$file=$curr_file;
									$registered_constants{'FILE'}=$file;
									$line_number=$curr_line_number;
								}
							}
							else
							{
								&logme("[WARNING] required file doesn't exist: $project_dir/$include_resolved_call_param, document_root: $project_dir, code:$code") if($debug_config{'WARNING'});
							}			 				
			 			}
			 			## [SHELL]
						&set_final_call_vulnerable('shell',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted) if(&in_array($called_function,"@shell_vulnerable_functions"));
						## [FOPEN]
						&set_final_call_vulnerable('fopen',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted,$nullbyte_required) if(&in_array($called_function,"@fopen_vulnerable_functions"));
			 			## [EVAL]
			 			&set_final_call_vulnerable('eval',$params_tracked_variable,$curr_local_virtual_line_number,'','',$line_copy,$registered_variables_trace{$params_tracked_variable},$is_tainted) if(&in_array($called_function,"@eval_vulnerable_functions"));
			 			## [SHELL]
			 			### END OF FLAW DETECTING SECTION, END OF CURRENT LINE TRACKING SECTION				  	  	
						### END OF CURRENT NEW CORE
					}	 ### END OF  USER_DEFINED/NATIVE ALTERNATIVE BLOCK					
					$param_index++;  ## parameter number
		 		} ##END OF PARAMETERS FOREACH
		 		#&logme("[WARNING] call params ($called_function($call_params)) do not contain tracked variable for $code") 	if(!$tracked_param_found&&$debug_config{'WARNING'});
				$code=substr $code, length($match)+1,length($code);  ## MATCH CUTOFF
 				$return_expr="$comma$called_function(".join(',',@parsed_call_params).")".&parse_expression($code,$left_side);
 				push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met&&&get_curr_func_name() ne '');
 				$nested_expressions--; 
				pop(@call_trace); 
				return $return_expr;
		 } 				 	
	## END OF FUNCTION CALL HANDLING BLOCK
	## 3 EVALUATION SECTION (string starts with variable or constant), completely rewritten, not tested
	## (comma separated arguments are temporarily not implemented and shall raise parse errors,
	## allowing all expressions to start with the optional comma should solve the issue
	## SO FAR, SO GOOD
	## constant checkups	
	if($code=~/^\s*(\w+)\s*/)
	{
		#	## constant found
		my $match=$&;
		$return_expr=$1;
		#print "[CONSTANT] $return_expr ($code)\n";
		#my $inset_const='';
		my $inset_const=$return_expr; ## changed after problems with parsing parameters with new algorithm
		if($registered_constants{$return_expr} ne undef)
		{
			$inset_const=$registered_constants{$return_expr};
		}
		else
		{
			if(!&in_array($return_expr,"@php_predefined_constants")&&!($return_expr=~/^\d+$/))
			{
				&logme("[WARNING] unknown constant $return_expr met at $file:$line_number ($line_copy).\n") if(!&in_array($return_expr,"@php_builtins")&&$debug_config{'WARNING'});
				$inset_const=$return_expr; ##
			}
			else
			{
				# - extend list of constants: 		'__CLASS__', '__DIR__', '__FILE__', '__FUNCTION__', '__LINE__' 
				$inset_const=$function_define_trace[scalar(@function_define_trace)-1] if($return_expr eq '__CLASS__'); ## temporary?
				$inset_const=$function_define_trace[scalar(@function_define_trace)-1] if($return_expr eq '__FUNCTION__');
				$inset_const=$function_define_trace[scalar(@function_define_trace)-1] if($return_expr eq '__METHOD__');
				$inset_const=$file if($return_expr eq '__FILE__');
				$inset_const=&dir_name($file) if($return_expr eq '__DIR__');
				$inset_const=$line_number if($return_expr eq '__LINE__');
			}
		}
		$code=~s/$match//;
		$return_expr=$comma.$inset_const.&parse_expression($code,$left_side);
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
		$nested_expressions--;
		return $return_expr;	
	}
 	## numeric constant
	if($code=~/^(\d+(\.\d+)?)/)
	{
		my $match=$&;
		$return_expr=$1;
		$code=~s/$match//; # instead of substr, it's fine
		$return_expr=$comma.$return_expr.&parse_expression($code,$left_side);
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
		$nested_expressions--;
		return $return_expr;
	}
	if($code=~/^$variable_preg/)
	{
		my $match=$&;
		my $new_var=$1;
		&logme("[DEBUG] evaluation section called for: $code") if($debug_config{'CALL'});
		&register_variable($new_var,'') if(!&variable_exists(&resolve_full_variable_namespace_path($new_var))); ## it's empty by default, so as in PHP
		my $new_var_regex=&escape_varname_to_regex($new_var);
		$code=~s/$new_var_regex//;
		my $post_expr=&parse_expression($code,$left_side);
		my $ret_string=$comma.&resolve_full_variable_namespace_path($new_var).$post_expr; # string for return
		push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($ret_string)) if($return_met);
		$return_expr=$ret_string;
		$nested_expressions--;
		return $return_expr;
	}
	
	### LAST SECTION TO REVIEW AND WE'RE GOING BACK TO TESTS
	my $buff='';
	my $char_before='';
	## now quotes section
	## ADD INTERPOLATION
	my $rep_code=$code;
	## this can be done much more elegant, but for now we have face another issue
	if($code=~/^"/) ## we start with double quot
	{
		#print "Ok, were here! This is string starting! $code\n";
		my $string_char_cnt=0;
		$rep_code=~s/^"//;
		$buff.='"';
		## here variable name interpolation comes into play: prematch.parse_line($var_name).postmatch
		while($rep_code=~/(.)/g) ## one char sequentially grabbing
		{
			$string_char_cnt++;
			if($string_char_cnt eq $max_string_length)
			{
				&logme("[ERROR] string longer than $max_string_length, truncating.") if($debug_config{'DEBUG'});
				$char_before='"';
				goto double_quot_parsed;
			}
			$buff.=$1;
			goto double_quot_parsed if($1 eq '"'&&ord($char_before) ne 92); ## it is possible to hang it by consuming whole memory with huge file with unclosed string
			$char_before=$1;
		}
	}
	double_quot_parsed:
	if($buff)
	{
			$code=substr $code,length($buff),length($code); ##
			$buff=~s/^"//;
			$buff=~s/"$//;
			## interpolation (currently only one variable)
			if($buff=~/$variable_preg/)
			{
				my $match=&parse_expression($&,$left_side);
				$buff=$`.$match.$'; # prematch+parsed+postmatch :DD
			}
			$return_expr=$comma.$buff.&parse_expression($code,$left_side);
			push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
			$nested_expressions--;
			return $return_expr;
	}
	### single quot parsing
	if($code=~/^\'/) ## instead of quot single
	{
		my $string_char_cnt=0;
		$rep_code=~s/^\'//;
		$buff.="'";
		while($rep_code=~/(.)/g) ##one char grabbing with quotes skipping
		{
			$string_char_cnt++;
			if($string_char_cnt eq $max_string_length)
			{
				&logme("[ERROR] string longer than $max_string_length, truncating.") if($debug_config{'DEBUG'});
				$char_before="'";
				goto single_quot_parsed;
			}
			$buff.=$1;
			goto single_quot_parsed if($1 eq "'" && ord($char_before) ne 92);
			$char_before=$1;
		}				
	}
	single_quot_parsed:
	if($buff)
	{
			$code=substr $code,length($buff),length($code);
			$buff=~s/^'//;
			$buff=~s/'$//;	
			$return_expr=$comma.$buff.&parse_expression($code,$left_side);
			push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
			$nested_expressions--;
			return $return_expr; 
	}
	
	## language constructs should hit this place
  	&logme("[ERROR] PARSE ERROR:$code") if($debug_config{'DEBUG'}&&$code!='<?php'&&$code!='?>');
  	push(@{$registered_functions{&get_curr_func_name()}{'returns'}},"$curr_local_virtual_line_number:".&cut_vars($return_expr)) if($return_met); 
  	$nested_expressions--;
  	return $comma.$code;
}
## this method is called after final call detection, it checks for sanitizing history in the current namespace -> it fills final_call_vulnerable hash
## ok, hereby I propose to change this method a bit and remove snitizing history check from it at all, since it should be done by calculate bugs anyway
## therefore this introduces only unnecessary mess, let's just fill final_call_vulnerable hash without worrying about $secured hash, since this is the job for calculate_bugs method]
# set_final_call_vulnerable($bug_type,$var_addr,$mapped_from_vline,$mapped_to_varaddr,$mapped_to_vline,$code,$code_trace,$external_is_tainted)
sub set_final_call_vulnerable
{
	my $bug_type=shift;
	my $var_addr=shift;
	my $mapped_from_vline=shift;
	my $mapped_to_varaddr=shift;
	my $mapped_to_vline=shift;
	my $code=shift;
	my $code_trace=shift; 
	my $external_is_tainted=shift;
	my $nullbyte_required=shift;  ## this one is currently optional and used only for LFI-s to detect NULLBYTE requirement, its use may be extended for SQL-s, fopen-s and so on
	$nullbyte_required=0 if($nullbyte_required eq undef);
	my $varname_preg=&varname_addr2preg($var_addr);
	$final_call_vulnerable{$bug_type}{$var_addr}=() if($final_call_vulnerable{$bug_type}{$var_addr} eq undef);
	#&logme("SET FINAL CALL VULN {$bug_type}{$var_addr} mapped_from_vline=>$mapped_from_vline, mapped_to_varaddr=>$mapped_to_varaddr, mapped_to_vline=>$mapped_to_vline, code=>$code, code_trace=>$code_trace, is_tainted=>$external_is_tainted, line=>$line_number, file=>$file");
	&logme("[WARNING] set_final_cal_vuln{$bug_type} called against empty variable on: $line_copy") if(!$var_addr&&$debug_config{'WARNING'});
	push(@{$final_call_vulnerable{$bug_type}{$var_addr}},{'mapped_from_vline'=>$mapped_from_vline,'mapped_to_varaddr'=>$mapped_to_varaddr,'mapped_to_vline'=>$mapped_to_vline,'code'=>$code,'code_trace'=>$code_trace,'is_tainted'=>$external_is_tainted,'line'=>$line_number,'file'=>$file,'desc'=>'','nullbyte'=>$nullbyte_required});
} 
sub calculate_bugs
{							
		my $rate;
		my $report_code;
		my $report_code_trace;
		my $report_desc;
		my $report_file;
		my $vuln_line;
		my $vuln_line_external;
		my $vuln_line_internal;
		my $vuln_var;
		my $nullbyte;
		foreach my $bug_group(keys %final_call_vulnerable)
		{
			 foreach my $variable_address(keys %{$final_call_vulnerable{$bug_group}})
			 {
				## iterate over all final call ocurrences, not just one
				for(my $i=0;$i<scalar(@{$final_call_vulnerable{$bug_group}{$variable_address}});$i++)
				{						
					next if($final_call_vulnerable{$bug_group}{$variable_address}[$i]{'is_tainted'} eq 0);
			 		$vuln_line_external=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'mapped_from_vline'}; 	
			 		$vuln_line_internal	=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'mapped_to_vline'}; 
			 		$vuln_var=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'mapped_to_varaddr'};
					$vuln_line=0;  
			 		$report_code=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'code'}; 
			 		$report_code_trace=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'code_trace'};
			 		$report_desc=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'desc'}; 	
			 		$vuln_line=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'line'}; 
			 		$report_file=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'file'};
					$nullbyte=$final_call_vulnerable{$bug_group}{$variable_address}[$i]{'nullbyte'};
			 		$rate=0;			 		
					## it increases the security rate variable as it encounters any security methods used
					## the higher is the security rate value, the smaller the chance the call is vulnerable (0 means 100% certainty of the flaw, 1 is more tentative flaw, 2 means tentative secure, 3 means rather secure, 4 means secure)
			 		foreach my $secure_bug_group(keys %{$final_secure_keys_relation{$bug_group}})
			 		{
							next if(scalar(keys %{$secured{$secure_bug_group}{$variable_address}}) eq 0); ## no security record at all
							my $durability;
							my $secure_line_external_start;
							my $secure_line_external_stop; # empty if there was no erasing instruction (overwrite or sth)
							my $secure_line_internal_start; # optional
							my $secure_line_internal_stop; # optional
							my $secure_internal_var; # optional
							my @secured_records;
					
							# SECTION 1
							durability_permanent:
							$durability='permanent';

							goto durability_volatile if($secured{$secure_bug_group}{$variable_address}{$durability} eq undef);
							@secured_records=@{$secured{$secure_bug_group}{$variable_address}{$durability}};
							for(my $j=0;$j<scalar(@secured_records);$j++)
							{
									my @secure_record=split(',',$secured_records[$j]);
									$secure_line_external_start=$secure_record[0];
									if($secure_record[1] ne undef)
									{
										$secure_internal_var=$secure_record[1];
									}
									else
									{
										$secure_internal_var='';
									}
									if($secure_record[2] ne undef)
									{
										$secure_line_internal_start=$secure_record[2]; 
									}
									else
									{
										$secure_line_internal_start='';
									}
									if($secure_line_external_start=~/(\d+)-(\d+)/)
									{
										$secure_line_external_start=$1;
										$secure_line_external_stop=$2;
									}
									else
									{
										$secure_line_external_stop='';
									}
									if($secure_line_internal_start=~/(\d+)-(\d+)/)
									{
										$secure_line_internal_start=$1;
										$secure_line_internal_stop=$2;
									}							
									else
									{
										$secure_line_internal_stop='';
									}
								#	print "Debug: secure_internal_var=$secure_internal_var and vuln_var: $vuln_var (durability: $durability)\n";
									next if($secure_internal_var ne $vuln_var&&$secure_line_internal_start); # make sure vlines belong to the same namespace ## THIS LOOKS OK (skip the security record values if the namespaces don't match to avoid false negatives)
									## for permanently secured, check the sequence ## THIS LOOKS OK 
									## increase the rate of security for this variable appropriate for the secure_bug_group functions group if range conditions are met
									if(($secure_line_external_start<$vuln_line_external&&($secure_line_external_stop eq ''||$secure_line_external_stop>$vuln_line_external))||($secure_line_external_start eq $vuln_line_external&&($secure_line_internal_start ne ''&&$vuln_line_internal ne ''&&$secure_line_internal_start<$vuln_line_internal))) 
									{
										#print "$secure_internal_var $durability secured record found (line: $secure_line_external_start)\n";
								#		print "$variable_address (internal:$secure_internal_var) $durability secured record found (line: $secure_line_external_start)\n";
										$rate+=$final_secure_keys_relation{$bug_group}{$secure_bug_group};
										goto durability_eof; # avoid duplicates
									}
				 		} # end of for on secured records	
				 			 		
				 		durability_volatile:
				 		# SECTION 2
				 		$durability='volatile';
				 #		print "Checking for {$secure_bug_group}{$variable_address}{$durability} record.\n";
				 		goto durability_eof if($secured{$secure_bug_group}{$variable_address}{$durability} eq undef);
				 		@secured_records=@{$secured{$secure_bug_group}{$variable_address}{$durability}};
				 		for(my $j=0;$j<scalar(@secured_records);$j++)
				 		{
						 		my @secure_record=split(',',$secured_records[$j]);
								$secure_line_external_start=$secure_record[0];
								if($secure_record[1] ne undef)
								{
									$secure_internal_var=$secure_record[1];
								}
								else
								{
									$secure_internal_var='';
								}
								if($secure_record[2] ne undef)
								{
									$secure_line_internal_start=$secure_record[2]; 
								}
								else
								{
									$secure_line_internal_start='';
								}
							#	print "Debug: secure_internal_var=$secure_internal_var and vuln_var: $vuln_var (durability: $durability)!\n";
								next if($secure_internal_var ne $vuln_var&&$secure_line_internal_start); # make sure vlines belong to the same namespace ## THIS LOOKS OK
					#			print "Debug2: secure_line_external_start = $secure_line_external_start, vuln_line_external = $vuln_line_external\n";
								if($secure_line_external_start eq $vuln_line_external&&$secure_line_internal_start eq $vuln_line_internal)
								{
						#			print "$variable_address (internal: $secure_internal_var) $durability secured record found (line: $secure_line_external_start)\n";
									$rate+=$final_secure_keys_relation{$bug_group}{$secure_bug_group};
									goto durability_eof;
								}				
				 		} # end of for on secured records
				 		durability_eof:
			 		} ## end of secure_bug_group foreach
			 		next if($rate ge 4); ## no way there is a flaw 
					#&report_vuln($rate,$bug_group,"$report_desc$report_file:$vuln_line:$variable_address:$report_code_trace"); # rate smaller than 4
					#my $reg_globals_suffix='';
					#$reg_globals_suffix=" (condition: register_globals ON)" if($variable_address=~/^\$[^_]+/);
					## we'll add support for reporting those fucks later (also ifs should be implemented)
					#&report_vuln($rate,$bug_group.$reg_globals_suffix,"$report_code_trace$report_file:$vuln_line:$report_code\n$report_desc"); # rate smaller than 4
					&report_vuln($rate,$bug_group,"$report_code_trace$report_file:$vuln_line:$report_code\n$report_desc",$nullbyte); # rate smaller than 4
			 }	# end of foreach on final_calls
		 }	 # end of foreach on 
	}
}
sub report_vuln
{
	my $rate=shift;
	my $bug_group=shift;
	my $report_desc=shift;
	my $nullbyte=shift;
	## rate is to be estimated
	$rate='-TENTATIVE' if($rate>0);
	$rate='' if($rate eq 0);
	my $reg_globals=1;
	foreach my $s_global(@tracked_superglobals)
	{
		if($report_desc=~/$s_global/)
		{
			$reg_globals=0;
			last;
		}
	}
	$rate.='-NULLBYTE_REQUIRED' if($nullbyte);
	$rate.='-REGISER_GLOBALS_REQUIRED' if($reg_globals);
	$bug_group =~ tr/a-z/A-Z/;
	my @report_desc_lines=split("\n",$report_desc);
	$report_desc_lines[scalar(grep $_,@report_desc_lines)-1]="[FINAL]".$report_desc_lines[scalar(grep $_,@report_desc_lines)-1]; ## mark the final call for easier result grouping
	foreach my $trace_line(@report_desc_lines) 
	{
		chomp($trace_line);
		$trace_line="\t[$bug_group$rate]$trace_line" if($trace_line);
	}
	$report_desc=join("\n",@report_desc_lines);
	&logme("[$bug_group$rate]\n$report_desc");
}
sub quiet_mode
{
	foreach my $k(keys %debug_config) { $debug_config{$k}=0; }
}
sub usage 
{
	print "$0 $version sca tool for PHP coded by ewilded\nUsage:\n$0 sca filename [options]\n$0 auto_tests\n$0 auto_sca project_dir\nOptions can be one of the following:\n-sensitivity=positive|negative";
	foreach my $output_key(keys %debug_config) { print " -$output_key=0|1"; }
	print "\n";
	## include options
}
### [RUN]
if(@ARGV<1) {  &usage(); exit; }
$work_dir=`pwd`;
chomp($work_dir);
my $cmd=$ARGV[0];
switch($cmd)
{
	case 'auto_tests'
	{
		## iterate over files, run itself with sca cmd, match output and report result
		my @tests=`ls $work_dir/tests/*.result`;
		my $tests_count=scalar(@tests);
		my $passed_tests=0;
		my $failed_tests=0;
		my $curr_test_num=0;
		foreach my $curr_test(@tests)
		{
			$curr_test_num++;
			chomp($curr_test);
			print "$curr_test ($curr_test_num/$tests_count)\t...";
			my $test_params='';
			my $test_name=$curr_test;
			$test_name=~s/\.result$//;
			open(f_params,"<$test_name.params");
			my $test_params=<f_params>;
			close(f_params);
			chomp($test_params);
			print "RUNNING perl $0 sca $test_name.php $test_params\n";
			my @curr_results=`perl $0 sca $test_name.php $test_params`;
			my @expected_results=`cat $test_name.result`;
			chomp($expected_results[0]);
			my $test_is_fine=0;
			my $curr_res_string="@curr_results";
			$curr_res_string=~s/\s*//g;
			$test_is_fine=1 if($curr_res_string=~/$expected_results[0]/m);
			if(!$test_is_fine) 
			{
				$failed_tests++;
				print color 'bold red';
				print "[FAILED]\n\n";
				print color 'reset';
			}
			else
			{
				$passed_tests++;
				print color 'bold green';
				print "[OK]\n\n";
				print color 'reset';
			}
		}
		my $accuracy=$passed_tests/$tests_count*100;
		printf "Passed $passed_tests, failed $failed_tests of $tests_count (accuracy %2.2f%%)\n",$accuracy;
	}
	case 'sca'
	{
		if($ARGV[1] eq undef) 
		{
			&usage();
			exit;
		}
		$f=$ARGV[1];
		if(not -f $f) { print "[ERROR] file $f does not exist!\n"; exit; }
		my @debug_config_keys=keys %debug_config;
		if(@ARGV>2)
		{
			my $curr_arg_num=2;
			while($ARGV[$curr_arg_num] ne undef)
			{
				if($ARGV[$curr_arg_num]=~/-sensitivity=(\w+)/)
				{
					$sensitivity=$1;
				}
				else
				{
					$ARGV[$curr_arg_num]=~/-(\w+)=(1|0)/;
					$debug_config{$1}=$2 if(&in_array($1,"@debug_config_keys"));
				}
				$curr_arg_num++;
			}
		}
		$registered_constants{'__FILE__'}=$f;
		$registered_constants{'DIRECTORY_SEPARATOR'}='/';
		my @full_path=split('/',$f);
#		my $full_dir=$work_dir.'/logs/'.$full_path[scalar(@full_path)-2];
#		`mkdir -p $full_dir`;
#		my $fname=$full_path[scalar(@full_path)-1];
		pop(@full_path);
		$project_dir=join('/',@full_path); ## project_dir is the directory where the file is present
		$project_dir='.' if($project_dir eq '');
		analyse_file($f);
		&calculate_bugs();
		## REPORT
		if($debug_config{'LIST_VARIABLES'})
		{
			&print_variables("\n\n[DEBUG] variables") ;
			&print_constants("\n\n[DEBUG] constants");
			&logme("\nTracked superglobals: ".&descape_varname_from_regex("@tracked_superglobals")."\n");
			&logme("\nTracked variables: ".&descape_varname_from_regex(@tracked_variables)."\n");
			&logme("\nAll functions used on input paramters: @called_functions\n");
		} 	
		&logme("\nIncluded files: @tracked_files");
		if($debug_config{'SUMMARY'})
		{
			if($warnings)
			{
				&logme("Found warnings summary:\n");
				print color 'bold yellow';
				print "$warnings\n";
				print color 'reset'; 
			}
			&logme("Found bugs summary:\n");
			$bugs='[NOTHING]' if(!$bugs);
			print color 'bold red';
			print "$bugs\n";
			print color 'reset';
		} 
	}
	case 'auto_sca'
	{
		$curr_line_tracked=LOCAL_VAL;
		$work_dir=$ARGV[1];
		print "\n\n\nAUTO SCA $work_dir STARTS\n\n\n";
		foreach my $entry(`find $work_dir -iname '*.php'`)
		{
			chomp($entry); # timeout 30 to avoid instances hanging due to buggy parsing (infinite loops etc.)
			print "Running timeout 30 perl $0 sca $entry\n";
			system("timeout 30 perl $0 sca $entry -INCLUDE=0 -REGISTER=0  -CALL=0 -DEBUG=0 -FUNCTION_DEFINITION=0 -EXPRESSION=0 -LIST_VARIABLES=0 -MERGE=0 -ERROR=1 -WARNING=0 -RESOLVE=0 -MATCH=0"); 
		}
	}
	default { &usage(); exit; }
}
