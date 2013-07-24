<?php
function f1($a)
{
	echo($a);
}
$c=$_GET['a'];
$d="../config/$c";
$d=trim($d);
echo($d);
?>