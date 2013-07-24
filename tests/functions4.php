<?php
function f1($a)
{
	echo($a);
	// final_call_vulnerable{xss}{f1::$a}=code=>'echo($a);'	,line=>4,current_local_virtual_line_number=>2
}
function f2($b)
{
	$b=trim($b);
	f1($b);
}
f2($_GET['page']);
?>