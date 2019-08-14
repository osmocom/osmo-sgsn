#!/usr/bin/env python2

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assert_(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assert_(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print >> sys.stderr, "Current directory: %s" % os.getcwd()
            print >> sys.stderr, "Consider setting -b"

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        osmoutil.end_proc(self.proc)


class TestVTYGbproxy(TestVTYBase):

    def vty_command(self):
        return ["./src/gprs/osmo-gbproxy", "-c",
                "doc/examples/osmo-gbproxy/osmo-gbproxy.cfg"]

    def vty_app(self):
        return (4246, "./src/gprs/osmo-gbproxy", "OsmoGbProxy", "gbproxy")

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('ns', ['']))
        self.assertEquals(self.vty.node(), 'config-ns')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('gbproxy', ['']))
        self.assertEquals(self.vty.node(), 'config-gbproxy')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')

    def testVtyShow(self):
        res = self.vty.command("show ns")
        self.assert_(res.find('Encapsulation NS-UDP-IP') >= 0)

        res = self.vty.command("show gbproxy stats")
        self.assert_(res.find('GBProxy Global Statistics') >= 0)

    def testVtyDeletePeer(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('delete-gbproxy-peer 9999 bvci 7777', ['BVC not found']))
        res = self.vty.command("delete-gbproxy-peer 9999 all dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') >= 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-bvc dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') >= 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') < 0)
        res = self.vty.command("delete-gbproxy-peer 9999 only-nsvc dry-run")
        self.assert_(res.find('Not Deleted 0 BVC') < 0)
        self.assert_(res.find('Not Deleted 0 NS-VC') >= 0)
        res = self.vty.command("delete-gbproxy-peer 9999 all")
        self.assert_(res.find('Deleted 0 BVC') >= 0)
        self.assert_(res.find('Deleted 0 NS-VC') >= 0)

class TestVTYSGSN(TestVTYBase):

    def vty_command(self):
        return ["./src/gprs/osmo-sgsn", "-c",
                "doc/examples/osmo-sgsn/osmo-sgsn-accept-all.cfg"]

    def vty_app(self):
        return (4245, "./src/gprs/osmo-sgsn", "OsmoSGSN", "sgsn")

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('ns', ['']))
        self.assertEquals(self.vty.node(), 'config-ns')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))
        self.assertEquals(self.vty.node(), 'config')

    def testVtyShow(self):
        res = self.vty.command("show ns")
        self.assert_(res.find('Encapsulation NS-UDP-IP') >= 0)
        self.assertTrue(self.vty.verify('show bssgp', ['']))
        self.assertTrue(self.vty.verify('show bssgp stats', ['']))
        self.assertTrue(self.vty.verify('show bssgp nsei 123', ['']))
        self.assertTrue(self.vty.verify('show bssgp nsei 123 stats', ['']))
        self.assertTrue(self.vty.verify('show sgsn', ['  GSN: signalling 127.0.0.1, user traffic 127.0.0.1']))
        self.assertTrue(self.vty.verify('show mm-context all', ['']))
        self.assertTrue(self.vty.verify('show mm-context imsi 000001234567', ['No MM context for IMSI 000001234567']))
        self.assertTrue(self.vty.verify('show pdp-context all', ['']))

        res = self.vty.command("show sndcp")
        self.assert_(res.find('State of SNDCP Entities') >= 0)

        res = self.vty.command("show llc")
        self.assert_(res.find('State of LLC Entities') >= 0)

    def testVtyAuth(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.assertTrue(self.vty.verify('auth-policy accept-all', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy accept-all') > 0)
        self.assertTrue(self.vty.verify('auth-policy acl-only', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy acl-only') > 0)
        self.assertTrue(self.vty.verify('auth-policy closed', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy closed') > 0)
        self.assertTrue(self.vty.verify('gsup remote-ip 127.0.0.4', ['']))
        self.assertTrue(self.vty.verify('gsup remote-port 2222', ['']))
        self.assertTrue(self.vty.verify('auth-policy remote', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('auth-policy remote') > 0)

    def testVtySubscriber(self):
        self.vty.enable()
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') < 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 create', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assert_(res.find('Authorized: 0') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 update-location-result ok', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assert_(res.find('Authorized: 1') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 cancel update-procedure', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') >= 0)
        self.assertTrue(self.vty.verify('update-subscriber imsi 1234567890 destroy', ['']))
        res = self.vty.command('show subscriber cache')
        self.assert_(res.find('1234567890') < 0)

    def testVtyGgsn(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')
        self.assertTrue(self.vty.verify('ggsn 0 remote-ip 127.99.99.99', ['']))
        self.assertTrue(self.vty.verify('ggsn 0 gtp-version 1', ['']))
        self.assertTrue(self.vty.verify('apn * ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn1.test ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn1.test ggsn 1', ['% a GGSN with id 1 has not been defined']))
        self.assertTrue(self.vty.verify('apn apn1.test imsi-prefix 123456 ggsn 0', ['']))
        self.assertTrue(self.vty.verify('apn apn2.test imsi-prefix 123456 ggsn 0', ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find('ggsn 0 remote-ip 127.99.99.99') >= 0)
        self.assert_(res.find('ggsn 0 gtp-version 1') >= 0)
        self.assert_(res.find('apn * ggsn 0') >= 0)
        self.assert_(res.find('apn apn1.test ggsn 0') >= 0)
        self.assert_(res.find('apn apn1.test imsi-prefix 123456 ggsn 0') >= 0)
        self.assert_(res.find('apn apn2.test imsi-prefix 123456 ggsn 0') >= 0)

    def testVtyEasyAPN(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')

        res = self.vty.command("show running-config")
        self.assertEquals(res.find("apn internet"), -1)

        self.assertTrue(self.vty.verify("access-point-name internet.apn", ['']))
        res = self.vty.command("show running-config")
        self.assert_(res.find("apn internet.apn ggsn 0") >= 0)

        self.assertTrue(self.vty.verify("no access-point-name internet.apn", ['']))
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("apn internet"), -1)

    def testVtyCDR(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')

        res = self.vty.command("show running-config")
        self.assert_(res.find("no cdr filename") > 0)

        self.vty.command("cdr filename bla.cdr")
        res = self.vty.command("show running-config")
        self.assertEquals(res.find("no cdr filename"), -1)
        self.assert_(res.find(" cdr filename bla.cdr") > 0)

        self.vty.command("no cdr filename")
        res = self.vty.command("show running-config")
        self.assert_(res.find("no cdr filename") > 0)
        self.assertEquals(res.find(" cdr filename bla.cdr"), -1)

        res = self.vty.command("show running-config")
        self.assert_(res.find(" cdr interval 600") > 0)

        self.vty.command("cdr interval 900")
        res = self.vty.command("show running-config")
        self.assert_(res.find(" cdr interval 900") > 0)
        self.assertEquals(res.find(" cdr interval 600"), -1)

    def testVtyTimers(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify('configure terminal', ['']))
        self.assertEquals(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify('sgsn', ['']))
        self.assertEquals(self.vty.node(), 'config-sgsn')

        for t in [3312, 3322, 3350, 3360, 3370, 3313, 3314, 3316, 3385, 3395, 3397]:
            self.assertTrue(self.vty.verify('timer t%d 10' % t, ['']))

def add_gbproxy_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/gprs/osmo-gbproxy")):
        print("Skipping the Gb-Proxy test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYGbproxy)
    suite.addTest(test)

def add_sgsn_test(suite, workdir):
    if not os.path.isfile(os.path.join(workdir, "src/gprs/osmo-sgsn")):
        print("Skipping the SGSN test")
        return
    test = unittest.TestLoader().loadTestsFromTestCase(TestVTYSGSN)
    suite.addTest(test)

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print "confpath %s, workdir %s" % (confpath, workdir)
    os.chdir(workdir)
    print "Running tests for specific VTY commands"
    suite = unittest.TestSuite()
    add_gbproxy_test(suite, workdir)
    add_sgsn_test(suite, workdir)

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
