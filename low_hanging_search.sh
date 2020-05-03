# grep the output for lowest-hanging fruits (pure high confidence stuff, no tentative, no terminator-required, no second-order)
GREPLOG=$1
grep '\[EXEC\]\|\[XSS\]\|\[SQL\]\|\[EVAL\]\|\[FOPEN\]\|\[SHELL\]|\[UPLOAD\]' $GREPLOG
