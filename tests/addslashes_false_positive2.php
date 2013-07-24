<?php
$b="SELECT id FROM t WHERE u= '".addslashes($_GET['id2']);
$b=htmlspecialchars($b);
mysql_query($b); ## NO SQL
# bez obslugi beznawiasowcow dziala ok:
#FALSE POSITIVE WORKAROUND (DYNAMIC LEFT SIDE): $b="SELECT id FROM t WHERE u= '".addslashes($_GET['id2']
#FALSE POSITIVE WORKAROUND2 single quotes count: 3
# z obsluga dziala nie ok:
#FALSE POSITIVE WORKAROUND (DYNAMIC LEFT SIDE): 
#FALSE POSITIVE WORKAROUND2 single quotes count: 0
 
?>