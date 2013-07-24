<?php
$a="SELECT something from t WHERE id={$_GET['id']} AND 1=2";
mysql_query($a); # SQL, XSS
?>