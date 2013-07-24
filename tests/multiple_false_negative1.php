<?php
$a=$_GET['id'];
mysql_query(int($a)); ## no SQL
mysql_query($a);  ## SQL! (expected false here, DiveInferno design error)
?>