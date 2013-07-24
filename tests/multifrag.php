<?php
$a=$_GET['a'];
mysql_query($a); # SQL no 1
$a=mysql_escape_string($a);
$a=$_GET['a'];
mysql_query($a); # SQL no 2
?>