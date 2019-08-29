#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_sgsn.h>

#ifdef BUILD_IU
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/ranap/iu_client.h>

void activate_pdp_rabs(struct sgsn_mm_ctx *ctx);
int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data);
int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp);

int gsm0408_gprs_rcvmsg_iu(struct msgb *msg, struct gprs_ra_id *ra_id, uint16_t *sai);
#endif

struct ranap_ue_conn_ctx;
/* On RANAP, Returns pointer to he associated ranap_ue_conn_ctx in msg, filled
 * in by osmo-iuh's iu_recv_cb().
 * On Gb, returns NULL */
#define MSG_IU_UE_CTX(msg) ((struct ranap_ue_conn_ctx *)(msg)->dst)
#define MSG_IU_UE_CTX_SET(msg, val) (msg)->dst = (val)
