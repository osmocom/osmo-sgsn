#pragma once

#include <osmocom/core/msgb.h>

#ifdef BUILD_IU
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/sgsn/iu_client.h>

struct sgsn_mm_ctx;
struct sgsn_pdp_ctx;

void activate_pdp_rabs(struct sgsn_mm_ctx *ctx);
int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data);
int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp);

/* free the Iu UE context */
void sgsn_ranap_iu_free(struct sgsn_mm_ctx *ctx);

/* send a Iu Release Command and free afterwards the UE context */
void sgsn_ranap_iu_release_free(struct sgsn_mm_ctx *ctx,
				const struct RANAP_Cause *cause);

#else /* ifndef BUILD_IU */
inline static void sgsn_ranap_iu_free(void *ctx) {};
inline static void sgsn_ranap_iu_release_free(void *ctx, void *cause) {};
#endif /* BUILD_IU*/

struct ranap_ue_conn_ctx;
/* On RANAP, Returns pointer to he associated ranap_ue_conn_ctx in msg, filled
 * in by osmo-iuh's iu_recv_cb().
 * On Gb, returns NULL */
#define MSG_IU_UE_CTX(msg) ((struct ranap_ue_conn_ctx *)(msg)->dst)
#define MSG_IU_UE_CTX_SET(msg, val) (msg)->dst = (val)
