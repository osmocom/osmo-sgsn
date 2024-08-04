SUBDIRS = \
	gprs \
	gtphub \
	gprs_routing_area \
	sgsn \
	xid \
	sndcp_xid \
	slhc \
	v42bis \
	$(NULL)

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
               echo '# Signature of the current package.' && \
               echo 'm4_define([AT_PACKAGE_NAME],' && \
               echo '  [$(PACKAGE_NAME)])' && \
               echo 'm4_define([AT_PACKAGE_TARNAME],' && \
               echo '  [$(PACKAGE_TARNAME)])' && \
               echo 'm4_define([AT_PACKAGE_VERSION],' && \
               echo '  [$(PACKAGE_VERSION)])' && \
               echo 'm4_define([AT_PACKAGE_STRING],' && \
               echo '  [$(PACKAGE_STRING)])' && \
               echo 'm4_define([AT_PACKAGE_BUGREPORT],' && \
               echo '  [$(PACKAGE_BUGREPORT)])'; \
               echo 'm4_define([AT_PACKAGE_URL],' && \
               echo '  [$(PACKAGE_URL)])'; \
             } >'$(srcdir)/package.m4'

EXTRA_DIST = \
	testsuite.at \
	$(srcdir)/package.m4 \
	$(TESTSUITE) \
	vty_test_runner.py \
	ctrl_test_runner.py \
	osmo-sgsn-accept-all.cfg \
	osmo-sgsn.cfg \
	osmo-sgsn_test-nodes.vty \
	$(NULL)

TESTSUITE = $(srcdir)/testsuite

DISTCLEANFILES = \
	atconfig \
	$(NULL)

if ENABLE_EXT_TESTS
python-tests:
	$(MAKE) vty-test
	$(MAKE) ctrl-python-test
else
python-tests:
	echo "Not running python-based tests (determined at configure-time)"
endif

vty-python-test: $(top_builddir)/src/sgsn/osmo-sgsn
	osmotestvty.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	osmotestconfig.py -p $(abs_top_srcdir) -w $(abs_top_builddir) -v
	$(srcdir)/vty_test_runner.py -w $(abs_top_builddir) -v
	rm -f $(top_builddir)/gsn_restart $(top_builddir)/gtphub_restart_count

# To update the VTY script from current application behavior,
# pass -u to vty_script_runner.py by doing:
#   make vty-transcript-test U=-u
vty-transcript-test: $(top_builddir)/src/sgsn/osmo-sgsn
	osmo_verify_transcript_vty.py -v \
		-n OsmoSGSN -p 4245 \
		-r "$(top_builddir)/src/sgsn/osmo-sgsn -c $(top_srcdir)/tests/osmo-sgsn.cfg" \
		$(U) $${T:-$(srcdir)/osmo-sgsn*.vty}
	rm -f $(builddir)/gsn_restart

# don't run multiple tests concurrently so that the ports don't conflict
vty-test:
	$(MAKE) vty-python-test
	$(MAKE) vty-transcript-test

ctrl-python-test: $(top_builddir)/src/sgsn/osmo-sgsn
	$(srcdir)/ctrl_test_runner.py -w $(abs_top_builddir) -v
	rm -f $(top_builddir)/gsn_restart $(top_builddir)/gtphub_restart_count

check-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)
	$(MAKE) $(AM_MAKEFLAGS) python-tests

installcheck-local: atconfig $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' \
		$(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOM4TE = $(SHELL) $(top_srcdir)/missing --run autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(srcdir)/testsuite.at $(srcdir)/package.m4
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
