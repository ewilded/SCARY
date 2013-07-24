<?php
$a=$_GET['a'];
?>
<h1>some ugly HTML</h1>
mysql_query($a); // look like function call
<?php
// XSS
echo($a); 
?>