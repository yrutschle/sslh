It is possible to run `sslh` on Windows. The `fork` model
should be avoided as it is very inefficient on Windows, but
`sslh-select` and `sslh-ev` both work with good performance
(prefer the latter, however).


The following script downloads the latest cygwin, the latest version of sslh, and then compiles and copies the binaries with dependancies to an output folder.

It may be needed to correct it from time to time, but it works. I use it in a virtual machine.
Just retrieve WGET.EXE from https://eternallybored.org/misc/wget/ or git binaries.

Copy the 3 files

	GO.cmd
	wget.exe
	compile.sh
	
to C root folder, then execute **GO.cmd** with administrative rights.

with **GO.cmd**

	@ECHO OFF
	CD /D "%~dp0"
	
	NET SESSION >NUL 2>&1
	IF %ERRORLEVEL% NEQ 0 (
	    ECHO Permission denied. This script must be run as an Administrator.
	    ECHO:
	    GOTO FIN
	) ELSE (
	    ECHO Running as Administrator.
	    TIMEOUT /T 2 >NUL
		wget --no-check-certificate https://www.cygwin.com/setup-x86_64.exe
		IF NOT EXIST setup-x86_64.exe GOTO FIN
		MKDIR C:\Z
		setup-x86_64.exe -l C:\Z -s ftp://ftp.funet.fi/pub/mirrors/sourceware.org/pub/cygwin/ -q -P make -P git -P gcc-g++ -P autoconf -P automake -P libtool -P libpcre-devel -P libpcre2-devel -P bison -P libev-devel
		MKDIR C:\cygwin64\home\user
	COPY COMPILE.SH C:\cygwin64\home\user
			START C:\cygwin64\bin\mintty.exe /bin/bash --login -i ~/compile.sh
		START EXPLORER C:\zzSORTIE
	)
	:FIN
	PAUSE
	EXIT


and **compile.sh**

	# SAVE FILE TO UNIX FORMAT
	# COPY IT IN C cygwin64 home user
	git clone https://github.com/hyperrealm/libconfig.git
	cd libconfig
	autoreconf -fi
	./configure
	make
	make install
	cd ..
	cp /usr/local/lib/libconfig.* /usr/lib
	git clone https://github.com/yrutschle/sslh.git
	cd sslh
	make
	cd ..
	mkdir /cygdrive/c/zzSORTIE
	cp ./sslh/sslh*.exe /cygdrive/c/zzSORTIE
	cp /usr/local/bin/cygconfig-11.dll /cygdrive/c/zzSORTIE
	cp /cygdrive/c/cygwin64/bin/cygwin1.dll /cygdrive/c/zzSORTIE
	cp /cygdrive/c/cygwin64/bin/cygpcreposix-0.dll /cygdrive/c/zzSORTIE
	cp /cygdrive/c/cygwin64/bin/cygpcre-1.dll /cygdrive/c/zzSORTIE
	cp /cygdrive/c/cygwin64/bin/cygev-4.dll /cygdrive/c/zzSORTIE
	cp /cygdrive/c/cygwin64/bin/cygpcre2-8-0.dll /cygdrive/c/zzSORTIE

This method was contributed by lerenardo on [github](https://github.com/yrutschle/sslh/issues/196#issuecomment-1692805639).
