SUBDIRS     = .
AM_CFLAGS   = $(WARNING_CFLAGS) $(AM_CPPFLAGS) $(PATHDEFS)
AM_CPPFLAGS = -I$(top_builddir) -I$(top_builddir)/src \
              -I$(top_srcdir) -I$(top_srcdir)/src
PATHDEFS    = -DSYSCONFDIR=\"${sysconfdir}\" \
              -DLIBDIR=\"${libdir}\" \
              -DLIBEXECDIR=\"${libexecdir}\"

systemd_DATA = flatpak-session@.service flatpak-sessions.target
systemddir   = ${libdir}/systemd/system

generator_PROGRAMS = flatpak-session-enable
generatordir       = ${libdir}/systemd/system-generators

session_SCRIPTS = start-session.sh
sessiondir      = ${libexecdir}/flatpak-utils

bin_PROGRAMS    =

#############################################
# flatpak-service-generator
#

bin_PROGRAMS += flatpak-session

flatpak_session_SOURCES =		\
		flatpak-session.c 	\
		config.c 		\
		mainloop.c		\
		remote.c		\
		application.c		\
		session.c		\
		flatpak.c		\
		filesystem.c		\
		log.c

flatpak_session_CFLAGS =		\
		$(AM_CFLAGS)		\
		$(PATHDEFS)		\
		$(FLATPAK_CFLAGS)

flatpak_session_LDADD =			\
		$(FLATPAK_LIBS)		\
		-lm

flatpak-session-enable: flatpak-session
	rm -f $@ && ln $< $@

# cleanup
clean-local:
	-rm -f *~
