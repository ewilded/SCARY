<?php
error_reporting(E_ALL);
define('some_path','lib/somepath');
define("some_suffix","_suffix");
$a="/directory/";
$b="/directory2/";
require(some_path . $a."$b/file.".some_suffix.".php");
## result should be:
## lib/somepath/directory//directory2//file._suffix.php
## and it is:
## ./lib/somepath/directory//directory2//file._suffix.php
## now check the dir and entry point compatibility
?>