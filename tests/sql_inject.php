<?php
// script.php?id=-1 UNION SELECT username,user_pass,email_addr FROM user--
mysql_query("SELECT id,title,content FROM news where id={$_GET['id']}"); // SQL inject
// turns into SELECT id,title,content FROM news where id=-1 UNION SELECT username,user_pass,email_addr FROM user--

#$_GET['id']=trim($_GET['id']); // regardless
#$_GET['id']=int($_GET['id']);	// untainting
#mysql_query("SELECT id,title,content FROM news where id={$_GET['id']}"); // no SQL inject
?>