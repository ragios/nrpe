#!/bin/sh
# Originated from https://git.io/autobuild 
#
# This script performs rpmbuild environment setup and the initial autotools bootstrapping.
# Abort the script and exit with failure if any command below exits with
# a non-zero exit status.
set -e

# Check needed software for building pnp4nagios on RL8
[ -e /usr/bin/autoconf ] || (echo "sudo dnf install -y autoconf";exit 1)
[ -e /usr/bin/automake ] || (echo "sudo dnf install -y automake";exit 1)
[ -e /usr/bin/rpmbuild ] || (echo "sudo dnf install -y rpm-build  redhat-rpm-config";exit 1)
[ -e ~/rpmbuild/BUILD  ] || (echo "mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}"   ;exit 1)
[ -e ~/.rpmmacros      ] || (echo "echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros" ;exit 1)
[ -e /usr/bin/gcc      ] || (echo "sudo dnf install -y gcc ";exit 1)
[ -e /usr/bin/make     ] || (echo "sudo dnf install -y make ";exit 1)
[ -e /usr/bin/libtool  ] || (echo "sudo dnf install -y libtool ";exit 1)
[ -e /usr/bin/perl     ] || (echo "sudo dnf install -y perl ";exit 1)
[ -e /usr/bin/rrdtool     ] || (echo "sudo dnf install -y rrdtool ";exit 1)
[ -e /usr/bin/h2xs    ] || (echo "sudo dnf install -y perl-devel ";exit 1)
[ -e /usr/lib64/perl5/vendor_perl/RRDp.pm    ] || (echo "sudo dnf install -y rrdtool-perl  ";exit 1)
[ -e /usr/bin/h2xs    ] || (echo "sudo dnf install -y perl-devel ";exit 1)
[ -e /usr/lib64/pkgconfig/openssl.pc   ] || (echo " sudo dnf install -y openssl-devel ";exit 1)
echo "rpmbuild environment is OK now."



# Create the m4/ directory if it doesn't exist.
[ -d m4 ] || mkdir m4
 
# If there's configure script, reconfigure the autoconf files. Make sure
# to install missing files and re-run configure and make if needed.
#[ -e ./configure ] || autoreconf -im
#aclocal && automake --gnu --add-missing && autoconf
#[ -e ./configure ] ||  ( rm -f configure && aclocal && autoconf )
[ -e ./configure ] || (aclocal && autoconf )

# If the Makefile doesn't exist, the previous step didn't run; this
# indicates the presence of a configure script. Run that script and
# then call make.
[ -e ./Makefile  ] ||  (rm -f Makefile)
./configure 
 
# If src/codename doesn't exist, there was a Makefile but make hasn't
# been run yet. Run it, which should produce the codename binary.
[ -e src/pnpsender.c ] || make
