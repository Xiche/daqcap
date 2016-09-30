
pkglibdir = $(libdir)/daq
pkglib_LTLIBRARIES = daq_daqcap.la

daq_daqcap_la_SOURCES = daq_daqcap.c
daq_daqcap_la_CPPFLAGS= $(AM_CPPFLAGS) $(LIBDAQ_CPPFLAGS) $(LIBSFBPF_CPPFLAGS) -I$(top_srcdir)/src
daq_daqcap_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
daq_daqcap_la_LIBADD  = ${top_builddir}/src/libdaqcap.la $(LIBSFBPF_LDFLAGS) -lsfbpf
