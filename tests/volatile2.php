<?php
function f3(&$c)
{
	$c=htmlspecialchars($c); ## filtering permanently
}
f3($_GET['a']);
echo($_GET['a']); # NOTHING
?>