<?php
function f1($a)
{
	return htmlspecialchars($a); ## filtering left side permanently
}
$b=f1($_GET['a']);
echo($b); # NOTHING
echo(htmlspecialchars($_GET['a'])); # NOTHING
echo($_GET['a']); # XSS
?>