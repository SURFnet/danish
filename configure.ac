###############################################################################
# Version information                                                          #
################################################################################

# Program version

define([DANISH_VERSION_MAJOR], [0])
define([DANISH_VERSION_MINOR], [2])
define([DANISH_VERSION_BUILDREV], esyscmd([sh -c "git rev-list --count HEAD|tr -d '\n'"]))
define([PACKAGE_SUFFIX], [])

################################################################################
# Configuration functions                                                      #
################################################################################

# Init
AC_PREREQ(2.61)
AC_INIT([danish],[DANISH_VERSION_MAJOR.DANISH_VERSION_MINOR.DANISH_VERSION_BUILDREV[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign subdir-objects)
ACX_PREFIXHACK

# Checks for compilers and other programs
AC_PROG_CC_C99
AC_PROG_INSTALL

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

# Libtool settings
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Check for libraries
PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.8], , AC_MSG_ERROR([OpenSSL cryptography library 0.9.8 or newer not found]))
AC_CHECK_LIB(crypto, BN_init)

# Check for headers
AC_HEADER_STDC

# Check for functions
AC_FUNC_MEMCMP
AC_CHECK_FUNC(strtok_r, , AC_MSG_ERROR([POSIX strtok_r function required]))

# Define default paths
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

# Define some variables for the code
AC_DEFINE_UNQUOTED(
	[VERSION_MAJOR],
	[DANISH_VERSION_MAJOR],
	[Major version number]
)
AC_DEFINE_UNQUOTED(
	[VERSION_MINOR],
	[DANISH_VERSION_MINOR],
	[Minor version number]
)

# Generate the install script
AC_PROG_INSTALL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
