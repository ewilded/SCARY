<?php
$a=f1($_GET['a']);

# $undefined_call{$_GET['a']}=(2,f1::1,); ## no mapped_to_vline since it's unknown
# when function definition is discovered, we search the unknown calls hash for its name
# $undefined_call{f1::1}=(2,$_GET['a'],) ## actually this would be more performant form
## ok, now we find function definition

## where $vline* is curr_local_virtual_line_number for its original namespace (f1 in this case)
# Now, what happens when f1($_GET['a']) is called (how final_call_vulnerable shall be merged):
# $final_call_vulnerable{xss}{$_GET['a']}=
#(
# mapped_from_vline,mapped_to_addr,mapped_to_vline,...
#)
# in this case:
# $final_call_vulnerable{xss}{$_GET['a']}=
# (
#	  (mapped_from_vline=>9,mapped_to_varaddr=>f1::$a, mapped_to_vline=>2)
#	  (mapped_from_vline=>9,mapped_to_varaddr=>f1::$a, mapped_to_vline=>4)
#   (mapped_from_vline=>11,mapped_to_varaddr=>f1::$a, mapped_to_vline=>2)
#   (mapped_from_vline=>11,mapped_to_varaddr=>f1::$a,mapped_to_vline=>4)
# )
#
# $secured{xss}{$_GET['a']}=
# (
#  9,f1::$a,3
#  9,f1::$a,5
# 11
# 12,f1::$a,3
# 12,f1::$a,5
# )

echo $a;
function f1($b)
{
	$b=htmlentities($b);
	return $b;
} 
## current result is [XSS],
## correct result is [NOTHING]
/*
	proposed solution:
		- if unknown function is run, run secure_var_lala on special 'undefined' key
		- when function definition is met, iterate over that hash and perform merge of the variables, so the taint checker will work
*/
?>