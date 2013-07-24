<?php
$a=$_GET['b'];
require_once('somepath/'.$a.'.php'); ## LFI with nullbyte required
?>