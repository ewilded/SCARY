<?php
function f2($b)
{
	echo($b);
}
function f1($c)
{
	## this shit doesn't work either
	$b=htmlspecialchars($c);
	return $b;
}
$A=$_POST['a'];
$A=f1($A);
f2($A);
?>