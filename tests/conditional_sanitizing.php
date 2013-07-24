<?php
$a=$_GET['b'];
if(isset($_COOKIE['admin'])) 
{
	$a=htmlspecialchars($a);
}
$b=$a; ## rewrite merge should save that counter
echo($a);
echo($b);

## save CONDITIONAL brackets counter for:
## 		- variable's registration
##		- variable's sanitizing call
## 		- variable's vuln call
## while performing taint checking (comparision in the same namespace, after merge),
## if sensitivity is set to 'positive', as it will be ( ;D ), ignore secure calls with higher conditional brackets number than vulnerable calls
### OR CONDITION IS DIFFERENT, TWO INDEPENDENT BLOCKS!  
?>