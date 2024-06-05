osmo-sgsn - Osmocom SGSN Implementation
=======================================

This repository contains a C-language implementation of a *Serving GPRS
Support Node (SGSN)* for 2.5/2.75G (GPRS/EDGE) and 3G (UMTS).  It is part of the
[Osmocom](https://osmocom.org/) Open Source Mobile Communications
project.

OsmoSGSN exposes

 * *Gb* towards PCUs (e.g. [OsmoPCU](https://osmocom.org/projects/osmopcu/wiki/OsmoPCU)): Various GbIP flavors + Gb/FR/E1
 * *GTP* towards a GGSN (e.g. [OsmoGGSN](https://osmocom.org/projects/openggsn/wiki))
 * IuPS over IP towards RNCs / HNBGW (e.g. [osmo-hnbgw](https://osmocom.org/projects/osmohnbgw/wiki))
 * The Osmocom typical telnet *VTY* and *CTRL* interfaces.
 * The Osmocom typical *statsd* exporter.
 * GSUP (custom MAP-like protocol) towards [osmo-hlr](https://osmocom.org/projects/osmo-hlr/wiki/OsmoHLR)

OsmoSGSN implements

 * GPRS mobility management
 * GPRS session management


Homepage
--------

You can find the OsmoSGSN homepage online at <https://osmocom.org/projects/osmosgsn/wiki>.


GIT Repository
--------------

You can clone from the official osmo-sgsn.git repository using

        git clone https://gitea.osmocom.org/cellular-infrastructure/osmo-sgsn

There is a web interface at <https://gitea.osmocom.org/cellular-infrastructure/osmo-sgsn>


Documentation
-------------

User Manuals and VTY reference manuals are [optionally] built in PDF form
as part of the build process.

Pre-rendered PDF version of the current "master" can be found at
[User Manual](https://ftp.osmocom.org/docs/latest/osmosgsn-usermanual.pdf)
as well as the [VTY Reference Manual](https://ftp.osmocom.org/docs/latest/osmosgsn-vty-reference.pdf)


Forum
-----

We welcome any osmo-sgsn related discussions in the
[Cellular Network Infratructure -> 2G/3G Core Network](https://discourse.osmocom.org/c/cni/2g-3g-cn).
section of the osmocom discourse (web based Forum).


Mailing List
------------

Discussions related to osmo-sgsn are happening on the
osmocom-net-gprs@lists.osmocom.org mailing list, please see
<https://lists.osmocom.org/postorius/lists/osmocom-net-gprs.lists.osmocom.org/> for subscription
options and the list archive.

Please observe the [Osmocom Mailing List
Rules](https://osmocom.org/projects/cellular-infrastructure/wiki/Mailing_List_Rules)
when posting.


Issue Tracker
-------------

We use the [issue tracker of the osmo-sgsn project on osmocom.org](https://osmocom.org/projects/osmosgsn/issues) for
tracking the state of bug reports and feature requests.  Feel free to submit any issues you may find, or help
us out by resolving existing issues.


Contributing
------------

Our coding standards are described at
<https://osmocom.org/projects/cellular-infrastructure/wiki/Coding_standards>

We use a Gerrit based patch submission/review process for managing
contributions.  Please see
<https://osmocom.org/projects/cellular-infrastructure/wiki/Gerrit> for
more details

The current patch queue for osmo-sgsn can be seen at
<https://gerrit.osmocom.org/#/q/project:osmo-sgsn+status:open>


History
-------

OsmoSGSN originated from the OpenBSC project, as a separate program within
openbsc.git. In 2017, OpenBSC was split in separate repositories, and hence
OsmoSGSN was given its own separate git repository.
