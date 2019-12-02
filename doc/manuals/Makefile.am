EXTRA_DIST = osmosgsn-usermanual.adoc \
    osmosgsn-usermanual-docinfo.xml \
    osmosgsn-vty-reference.xml \
    osmogbproxy-usermanual.adoc \
    osmogbproxy-usermanual-docinfo.xml \
    regen_doc.sh \
    chapters \
    vty \
    osmogbproxy-vty-reference.xml \
    vty-osmogbproxy \
    $(NULL)

if BUILD_MANUALS
  ASCIIDOC = osmosgsn-usermanual.adoc osmogbproxy-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmosgsn-vty-reference.xml osmogbproxy-vty-reference.xml
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-sgsn
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
