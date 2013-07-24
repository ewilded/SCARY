<?php
function f1($a)
{
	echo($a);
	$a=htmlspecialchars($a);
	echo($a);
	$a=htmlspecialchars($a);
	$a=f2($a);
}
f1($_GET['a']); ## XSS
$_GET['a']=htmlspecialchars($_GET['a']);
f1($_GET['a']); ## nothing
mysql_query($_GET['a']); #SQL (no return)
function f2($b)
{
	$b=mysql_escape_string($b);
}
?>
