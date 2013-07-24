<?php
# entry point, vuln
function f1($a)
{
	echo($a);
}
function f2($b)
{
	f1($b);
}
f2($_GET['a']);
?>