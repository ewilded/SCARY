<?php
function f1($a)
{
	echo($a);		// final_call_vulnerable{xss}{f1::$a}=code=>'echo($a);'	,line=>4,current_local_virtual_line_number=>2
}
function f2($b)
{
	$b=trim($b);
	$b=f3($b); //  secured{xss}{f2::$b}
	f1($b);
}
function f3($c)
{
	$c=htmlspecialchars($c);		// $secured{xss}{f3::$c}=>'f3:2' (format: call's namespace, current_virtual_line_number) 
	if($c!='') return $c; // added to returns (variable+vline)
	#return $_GET['b']; // added to returns (variable+vline)
}
f2($_GET['page']); // NOTHING
?>