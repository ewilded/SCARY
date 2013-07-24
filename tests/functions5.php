<?php
## [OK]
function f1($a)
{
	echo($a);
}
$b=htmlspecialchars($_GET['b']); ##
f1($b); ## no flaw (secured{$b|7|f1::$a} - external->internal mapping has to be done this way (prefixed by the superior origin of history)
$c=htmlspecialchars($_GET['c']);
f1($c); ##  no flaw (secured{$c|9|f1::$a} - external->internal mapping again, other case
f1($_GET['b']); ## flaw (no secured $_GET['b'])
?>