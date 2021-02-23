EXTRA_DIST = osmosgsn-usermanual.adoc \
    osmosgsn-usermanual-docinfo.xml \
    osmosgsn-vty-reference.xml \
    regen_doc.sh \
    chapters \
    vty \
    $(NULL)

if BUILD_MANUALS
  ASCIIDOC = osmosgsn-usermanual.adoc
  ASCIIDOC_DEPS = $(srcdir)/chapters/*.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc

  VTY_REFERENCE = osmosgsn-vty-reference.xml

  BUILT_REFERENCE_XML = $(builddir)/vty/sgsn_vty_reference.xml
  $(builddir)/vty/sgsn_vty_reference.xml: $(top_builddir)/src/sgsn/osmo-sgsn
	mkdir -p $(builddir)/vty
	$(top_builddir)/src/sgsn/osmo-sgsn --vty-ref-xml > $@

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.vty-reference.inc

  OSMO_REPOSITORY = osmo-sgsn
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
