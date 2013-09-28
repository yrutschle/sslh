#! /bin/bash

if [ ${#} -eq 1 ] && [ "x$1" = "x-r" ]; then
	# release text only
	QUIET=1
else
	QUIET=0
fi

if head=`git rev-parse --verify HEAD 2>/dev/null`; then

	if [ $QUIET -ne 1 ]; then
		printf "#ifndef _VERSION_H_ \n"
		printf "#define _VERSION_H_ \n\n"
		printf "#define VERSION \""
	fi

	# generate the version info based on the tag
	(git describe --tags || git --describe || git describe --all --long) \
		2>/dev/null | tr -d '\n'

	# Are there uncommitted changes?
	git update-index --refresh --unmerged > /dev/null
	if git diff-index --name-only HEAD | grep -v "^scripts/package" \
	    | read dummy; then
		printf '%s' -dirty
	fi

	if [ $QUIET -ne 1 ]; then
		printf "\"\n"
		printf "\n#endif\n"
	fi
fi
