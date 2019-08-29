#pragma once

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_rllc.h>

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
