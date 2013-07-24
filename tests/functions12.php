<?php
function f1($a)
{
	## test for globals working properly
	echo($_GET['b']); 
}
f1(0);
# XSS
?>