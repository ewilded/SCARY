<?php
function f2($b)
{
	$b=htmlspecialchars($b);
	return $b;	# filtering left side permanently
}
echo(f2($_GET['a'])); # NOTHING
echo($_GET['a']); # XSS
?>