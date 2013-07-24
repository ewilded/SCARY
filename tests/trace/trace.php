<?php
function f2($b)
{
	shell_exec($b);
}
function f1($a)
{
		f2($a);
}

$c=$_REQUEST['content'];
$c=trim($c);
$d="../config/$c";
f1($d);
?>
