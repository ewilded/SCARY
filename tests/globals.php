<?php
$a=$_GET['a'];
function f1($b)
{
	global $a;
	## test for globals working properly no 2
	echo($a); 
}
f1(2); #
?>