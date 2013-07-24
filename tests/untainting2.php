<?php
$a='SELECT * FROM user WHERE id='.$_GET['id'].' AND 1=1';
if(1==1) $a='SELECT * FROM USER WHERE id=1'; ## untainting
mysql_query($a);
?>