#pragma once

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_llc.h>

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
/* Has to be called whenever any PDU (signaling, data, ...) has been received */
void gprs_gb_recv_pdu(struct sgsn_mm_ctx *mmctx);
