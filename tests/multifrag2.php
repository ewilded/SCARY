<?php
$a=$_GET['a'];
echo($a); # XSS no 1
$a=htmlspecialchars($a);
$a=$_GET['a'];
echo($a); # XSS no 2
?>