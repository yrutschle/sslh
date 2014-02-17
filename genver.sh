#! /bin/sh

if [ ${#} -eq 1 ] && [ "x$1" = "x-r" ]; then
	# release text only
	QUIET=1
else
	QUIET=0
fi

if ! `(git status | grep -q "On branch") 2> /dev/null`; then
        # If we don't have git, we can't work out what
        # version this is. It must have been downloaded as a
        # zip file. Github creates the zip file with all
        # files dated from the last change: use the
        # Makefile's modification time as a release number
	release=zip-`stat -c "%y" Makefile | sed 's/ .*//'`
fi

if head=`git rev-parse --verify HEAD 2>/dev/null`; then
	# generate the version info based on the tag
	release=`(git describe --tags || git --describe || git describe --all --long) \
		2>/dev/null | tr -d '\n'`

	# Are there uncommitted changes?
	git update-index --refresh --unmerged > /dev/null
	if git diff-index --name-only HEAD | grep -v "^scripts/package" \
	    | read dummy; then
		release="$release-dirty"
	fi
fi


if [ $QUIET -ne 1 ]; then
	printf "#ifndef _VERSION_H_ \n"
	printf "#define _VERSION_H_ \n\n"
	printf "#define VERSION \"$release\"\n"
	printf "#endif\n"
else
	printf "$release\n"
fi
