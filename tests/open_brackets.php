<?php
function f1($a){
	if(1==2)
	{
		
	}
	#XSS
	echo($a);
}
f1($_GET['a']);

?>