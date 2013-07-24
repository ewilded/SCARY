<?php
$c=addslashes($_GET['id2']);
$b="SELECT id FROM t WHERE u= '".$c; ## still getting false positive on this one
mysql_query($b); ## SQL 
?>