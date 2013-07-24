<?php
## to sie jebie, bo nie jest przekazany left_side rekurencyjnie do podwywolania
$b="SELECT id FROM t WHERE u= '".htmlspecialchars(addslashes($_GET['id2']));
mysql_query($b); ## NOTHING
?>