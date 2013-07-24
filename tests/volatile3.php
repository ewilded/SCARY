<?php
function f4(&$d)
{
	htmlspecialchars($d); ## doing nothing
}
echo(1);
f4($_GET['a']); 
echo($_GET['a']);
?>