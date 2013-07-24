<?php
# [OK]
function f2($b)
{
	$b=htmlspecialchars($b);
	return($b);
}
$A=$_POST['b'];
$A=f2($A);
echo($A);
?>