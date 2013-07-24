<?php
## entry point, not vuln
function f1($a)
{
	echo($a);
}
function f2($b)
{
	f1($a);
}
f2($a);
?>