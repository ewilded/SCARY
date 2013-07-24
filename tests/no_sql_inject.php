<?php
$a='SELECT chuj FROM dupa';
$a.=" WHERE id={$_GET['id']}";
mysql_query($a);
?>