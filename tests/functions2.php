<?php
function f2($b)
{
	echo($b);
}
function f1($c)
{
	$c=htmlspecialchars($c);
	return $c;
}
$A=$_POST['b'];
$A=f1($A);
f2($A);
?>