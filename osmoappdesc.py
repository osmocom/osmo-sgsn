#!/usr/bin/env python

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


app_configs = {
    "gbproxy": ["doc/examples/osmo-gbproxy/osmo-gbproxy.cfg",
             "doc/examples/osmo-gbproxy/osmo-gbproxy-legacy.cfg"],
    "sgsn": ["doc/examples/osmo-sgsn/osmo-sgsn.cfg"],
    "gtphub": ["doc/examples/osmo-gtphub/osmo-gtphub-1iface.cfg"]
}


apps = [(4246, "src/gbproxy/osmo-gbproxy", "OsmoGbProxy", "gbproxy"),
        (4245, "src/gprs/osmo-sgsn", "OsmoSGSN", "sgsn"),
        (4253, "src/gprs/osmo-gtphub", "OsmoGTPhub", "gtphub")
        ]

vty_command = ["./src/gprs/osmo-sgsn", "-c",
               "doc/examples/osmo-sgsn/osmo-sgsn.cfg"]

vty_app = apps[1]
