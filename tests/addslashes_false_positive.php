<?php
$b="SELECT id FROM t WHERE u=".addslashes($_GET['id2']);
$b=htmlspecialchars($b);
mysql_query($b); ## SQL 
?>