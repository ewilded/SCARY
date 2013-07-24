<?php
# not entry point, vuln
function f1($a)
{
	echo($a);
}
function f2($b)
{
	echo($_GET['a']);
}
if(!defined('SOME_CONST')) die();
f2(3);
?>
