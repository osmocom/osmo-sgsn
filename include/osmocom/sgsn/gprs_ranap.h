#pragma once

#include "config.h"

#include <osmocom/core/msgb.h>

#ifdef BUILD_IU
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/sccp.h>

struct sgsn_mm_ctx;
struct sgsn_pdp_ctx;

/* struct RANAP_GlobalRNC_ID with a coupled buffer where .buf points to.
 * Used to easily generate a struct RANAP_GlobalRNC_ID to encode,
 * see sgsn_ranap_iu_grnc_id_compose(). */
struct iu_grnc_id {
	uint8_t plmn_buf[3];
	struct RANAP_GlobalRNC_ID grnc_id;
};
int sgsn_ranap_iu_grnc_id_compose(struct iu_grnc_id *dst, const struct osmo_rnc_id *src);

int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data);

int sgsn_ranap_iu_tx(struct msgb *msg, uint8_t sapi);
int sgsn_ranap_iu_tx_rab_ps_ass_req(struct ranap_ue_conn_ctx *ue_ctx,
				    uint8_t rab_id, uint32_t gtp_ip, uint32_t gtp_tei);
int sgsn_ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
			     int send_ck, int new_key);
int sgsn_ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *ue_ctx, const char *imsi);

int sgsn_ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause);
/* Transmit a Iu Release Command and submit event RANAP_IU_EVENT_IU_RELEASE upon
 * Release Complete or timeout. Caller is responsible to free the context and
 * closing the SCCP connection (sgsn_ranap_iu_free_ue) upon recieval of the event. */
void sgsn_ranap_iu_tx_release_free(struct ranap_ue_conn_ctx *ctx,
			      const struct RANAP_Cause *cause,
			      int timeout);

int sgsn_ranap_iu_tx_cl(struct sgsn_sccp_user_iups *scu_iups,
			const struct osmo_sccp_addr *dst_addr,
			struct msgb *msg);
int sgsn_ranap_iu_tx_error_ind(struct sgsn_sccp_user_iups *scu_iups,
			       const struct osmo_sccp_addr *dst_addr,
			       const RANAP_Cause_t *cause);

void sgsn_ranap_iu_handle_co_initial(struct ranap_iu_rnc *iu_rnc,
				     uint32_t conn_id,
				     const ranap_message *message);
void sgsn_ranap_iu_handle_co(struct ranap_ue_conn_ctx *ue_ctx, const ranap_message *message);

/* Entry points from rx SCCP: */
int sgsn_ranap_iu_rx_cl_msg(struct sgsn_sccp_user_iups *scu_iups,
			    const struct osmo_scu_unitdata_param *ud_prim,
			    const uint8_t *data, size_t len);
int sgsn_ranap_iu_rx_co_initial_msg(struct sgsn_sccp_user_iups *scu_iups,
				    const struct osmo_sccp_addr *rem_sccp_addr,
				    uint32_t conn_id,
				    const uint8_t *data, size_t len);
int sgsn_ranap_iu_rx_co_msg(struct ranap_ue_conn_ctx *ue_ctx, const uint8_t *data, size_t len);

#endif /* ifdef BUILD_IU */

struct ranap_ue_conn_ctx;
/* On RANAP, Returns pointer to he associated ranap_ue_conn_ctx in msg, filled
 * in by osmo-iuh's iu_recv_cb().
 * On Gb, returns NULL */
#define MSG_IU_UE_CTX(msg) ((struct ranap_ue_conn_ctx *)(msg)->dst)
#define MSG_IU_UE_CTX_SET(msg, val) (msg)->dst = (val)
