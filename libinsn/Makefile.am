AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_LDFLAGS = -L/usr/local/lib/ $(libgeneral_LIBS)

lib_LTLIBRARIES = libinsn.la

libinsn_la_CPPFLAGS = $(AM_CFLAGS)
libinsn_la_LIBADD = $(AM_LDFLAGS)
libinsn_la_SOURCES = 	insn_decode.cpp \
											insn_encode.cpp \
											vsegment.cpp \
											vmem.cpp

											
