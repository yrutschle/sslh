#! /bin/sh

if [ ${#} -eq 1 ] && [ "x$1" = "x-r" ]; then
	# release text only
	QUIET=1
else
	QUIET=0
fi

if [ ! -d .git ] || ! `(git status | grep -q "On branch") 2> /dev/null`; then
        # If we don't have git, we can't work out what
        # version this is. It must have been downloaded as a
        # zip file.

        # If downloaded from the release page, the directory
        # has the version number.
        release=`pwd | sed s/.*sslh-// | grep "[[:digit:]]"`

        if [ "x$release" = "x" ]; then
            # If downloaded from the head, GitHub creates the
            # zip file with all files dated from the last
            # change: use the Makefile's modification time as a
            # release number
            release=head-`perl -MPOSIX -e 'print strftime "%Y-%m-%d",localtime((stat "Makefile")[9])'`
        fi
fi

if [ -d .git ] && head=`git rev-parse --verify HEAD 2>/dev/null`; then
	# generate the version info based on the tag
	release=`(git describe --tags || git --describe || git describe --all --long) \
		2>/dev/null | tr -s '/' '-' | tr -d '\n'`

	# Are there uncommitted changes?
	git update-index --refresh --unmerged > /dev/null
	if git diff-index --name-only HEAD | grep -v "^scripts/package" \
	    | read dummy; then
		release="$release-dirty"
	fi
fi


if [ $QUIET -ne 1 ]; then
	printf "#ifndef VERSION_H \n"
	printf "#define VERSION_H \n\n"
	printf "#define VERSION \"$release\"\n"
	printf "#endif\n"
else
	printf "$release\n"
fi
