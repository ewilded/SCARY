<?php
# this one's directly from  php.net ;D
#$html = $_POST['html'];
#$html = preg_replace('(<h([1-6])>(.*?)</h\1>)e','"<h$1>" . strtoupper("$2") . "</h$1>"',$html);
$html = $_POST['html'];
$html = preg_replace('(.*)e','"<h$1>" . strtoupper("$2") . "</h$1>"',$html);
?>