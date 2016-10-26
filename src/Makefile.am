SUBDIRS     = .
AM_CFLAGS   = $(WARNING_CFLAGS) $(AM_CPPFLAGS) $(PATHDEFS)
AM_CPPFLAGS = -I$(top_builddir) -I$(top_builddir)/src \
              -I$(top_srcdir) -I$(top_srcdir)/src
PATHDEFS    = -DSYSCONFDIR=\"${sysconfdir}\" \
              -DLIBDIR=\"${libdir}\" \
              -DLIBEXECDIR=\"${libexecdir}\"

#############################################
# flatpak-service-generator
#

systemd_generator_PROGRAMS = flatpak-service-generator
systemd_generatordir = /lib/systemd/system-generators

flatpak_service_generator_SOURCES =		\
		flatpak-service-generator.c	\
		config.c			\
		flatpak.c			\
		service.c			\
		filesystem.c			\
		template.c			\
		log.c

flatpak_service_generator_CFLAGS =		\
		$(AM_CFLAGS)			\
		$(PATHDEFS)			\
		$(FLATPAK_CFLAGS)

flatpak_service_generator_LDADD =		\
		$(FLATPAK_LIBS)			\
		-lm

SERVICE_TEMPLATES =       			\
		flatpak-service.template

SYSTEMD_UNITS = 	      		\
		flatpaks.target

# Install service file template(s).
install-service-templates:
	install -d $(DESTDIR)${libexecdir}/flatpak-utils && \
	    cp $(top_srcdir)/$(SERVICE_TERMPLATES) \
	       $(DESTDIR)/${libexecdir}/flatpak-utils

# Install units for systemd.
install-systemd-units:
	mkdir -p $(DESTDIR)/lib/systemd/system
	    cp $(top_srcdir)/src/$(SYSTEMD_UNITS) \
	        $(DESTDIR)/lib/systemd/system

# Install various runtime data we need.
install-data-hook: install-service-templates install-systemd-units

# cleanup
clean-local:
	-rm -f *~
