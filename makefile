VERSION := ascon128v12
OPT     := opt64

.PHONY : copy
copy :
	# Update the local copy of the code with upstream reference
	# implementation from git submodule.
	(cd ascon-reference/$(VERSION)/$(OPT) && tar c *.h *.c) | tar xv