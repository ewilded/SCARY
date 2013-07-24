<?php
$a=$_GET['b'];
require_once('somepath/'.$a ); ## LFI without nullbyte required
?>