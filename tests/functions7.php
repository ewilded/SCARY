<?php
# [OK]
function f2($b)
{
	$b=htmlspecialchars($b);
	return $b;
}
$A=$_POST['b'];
echo($A);
$A=f2($A);
# flaw (too late)
?>