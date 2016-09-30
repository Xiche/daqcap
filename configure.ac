
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

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for the DAQ and SFBPF headers/library.
AC_CHECK_DAQ
if test "x$HAVE_DAQ_HEADERS" != "xyes"; then
    AC_MSG_ERROR([Could not find LibDAQ headers!])
fi
AM_CONDITIONAL([BUILD_DAQCAP_EXAMPLE], [test "x$HAVE_DAQ_LIBRARIES" != "xno"])

AC_CHECK_SFBPF
if test "x$HAVE_SFBPF_HEADERS" != "xyes"; then
    AC_MSG_ERROR([Could not find LibSFBPF headers!])
fi
AM_CONDITIONAL([BUILD_DAQCAP_MODULE], [test "x$HAVE_SFBPF_LIBRARIES" != "xno"])

# Checks for library functions.
AC_CHECK_FUNCS([strerror])

AM_CPPFLAGS=-Wall

AC_CONFIG_FILES([ \
Makefile \
example/Makefile \
module/Makefile \
src/Makefile \
])

AC_SUBST([LIBDAQ_CPPFLAGS])
AC_SUBST([LIBDAQ_LDFLAGS])
AC_SUBST([LIBSFBPF_CPPFLAGS])
AC_SUBST([LIBSFBPF_LDFLAGS])

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
    daq_cppflags:   ${LIBDAQ_CPPFLAGS}
    sfbpf_cppflags: ${LIBSFBPF_CPPFLAGS}
    am_cxxflags:    ${AM_CXXFLAGS}
    cflags:         ${CFLAGS}
    am_cflags:      ${AM_CFLAGS}
    ldflags:        ${LDFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
    daq_ldflags:    ${LIBDAQ_LDFLAGS}
    sfbpf_ldflags:  ${LIBSFBPF_LDFLAGS}
    libs:           ${LIBS}
])
