# $Id: acx_strict.m4 42 2013-06-20 12:47:04Z rijswijk $

AC_DEFUN([ACX_STRICT],[
	AC_ARG_ENABLE(
		[strict],
		[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@enabled@:>@])],
		,
		[enable_strict="yes"]
	)
	if test "${enable_strict}" = "yes"; then
		CFLAGS="${CFLAGS} -Wall -Wextra"
	fi
])
