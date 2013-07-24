<?php
$b="SELECT ".$_GET['id'];
$b=htmlspecialchars($b);
mysql_query($b); ## SQL
?>