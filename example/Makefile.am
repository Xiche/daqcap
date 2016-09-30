
bin_PROGRAMS = daqcap

daqcap_SOURCES = daqcap.c
daqcap_CPPFLAGS = $(AM_CPPFLAGS) $(LIBDAQ_CPPFLAGS) -I$(top_srcdir)/src
daqcap_LDADD = ${top_builddir}/src/libdaqcap.la $(LIBDAQ_LDFLAGS) -ldaq
