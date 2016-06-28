
AC_PREREQ([2.69])
AC_INIT([daqcap], [0.1], [michael@theoddone.net])
AC_CONFIG_SRCDIR([src/daq_capture.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
LT_INIT

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_CHECK_FUNCS([strerror])

AM_CPPFLAGS=-Wall

AC_CONFIG_FILES([ \
Makefile \
src/Makefile \
module/Makefile \
])

AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    cc:             ${CC}
    cppflags:       ${CPPFLAGS}
    am_cppflags:    ${AM_CPPFLAGS}
    am_cxxflags:    ${AM_CXXFLAGS}
    cflags:         ${CFLAGS}
    am_cflags:      ${AM_CFLAGS}
    ldflags:        ${LDFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
    libs:           ${LIBS}
])
