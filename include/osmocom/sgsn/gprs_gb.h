#pragma once

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_llc.h>

/* called by the ns layer */
int gprs_ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx);
