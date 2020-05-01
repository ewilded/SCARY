# grep the output for lowest-hanging fruits
GREPLOG=$1
grep '\[EXEC\]\|\[XSS\]\|\[SQL\]\|\[EVAL\]\|\[FOPEN\]\|\[SHELL\]' $GREPLOG
