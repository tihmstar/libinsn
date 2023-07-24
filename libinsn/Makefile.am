AM_CFLAGS = -I$(top_srcdir)/include $(libgeneral_CFLAGS)
AM_LDFLAGS = $(libgeneral_LIBS)

lib_LTLIBRARIES = libinsn.la

libinsn_la_CPPFLAGS = $(AM_CFLAGS)
libinsn_la_LIBADD = $(AM_LDFLAGS)
libinsn_la_SOURCES = 	arm64_decode.cpp \
						arm64_encode.cpp \
						arm32_arm_decode.cpp \
						arm32_arm_encode.cpp \
						arm32_thumb_decode.cpp \
						arm32_thumb_encode.cpp \
						vmem.cpp
