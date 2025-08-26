#pragma once

#include <osmocom/core/msgb.h>

#ifdef BUILD_IU
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/sccp.h>

struct sgsn_mm_ctx;
struct sgsn_pdp_ctx;

void activate_pdp_rabs(struct sgsn_mm_ctx *ctx);
int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data);
int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp);

int ranap_iu_tx(struct msgb *msg, uint8_t sapi);
int ranap_iu_rab_act(struct ranap_ue_conn_ctx *ue_ctx, struct msgb *msg);
int ranap_iu_rab_deact(struct ranap_ue_conn_ctx *ue_ctx, uint8_t rab_id);
int ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
			     int send_ck, int new_key);
int ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *ue_ctx, const char *imsi);
int ranap_iu_tx_paging_cmd(struct osmo_sccp_addr *called_addr,
		     const char *imsi, const uint32_t *tmsi,
		     bool is_ps, uint32_t paging_cause);

int ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause);
/* Transmit a Iu Release Command and submit event RANAP_IU_EVENT_IU_RELEASE upon
 * Release Complete or timeout. Caller is responsible to free the context and
 * closing the SCCP connection (ranap_iu_free_ue) upon recieval of the event. */
void ranap_iu_tx_release_free(struct ranap_ue_conn_ctx *ctx,
			      const struct RANAP_Cause *cause,
			      int timeout);

/* free the Iu UE context */
void sgsn_ranap_iu_free(struct sgsn_mm_ctx *ctx);

/* send a Iu Release Command and free afterwards the UE context */
void sgsn_ranap_iu_release_free(struct sgsn_mm_ctx *ctx,
				const struct RANAP_Cause *cause);

int sgsn_ranap_iu_rx_cl_msg(struct sgsn_sccp_user_iups *scu_iups, struct osmo_scu_unitdata_param *ud_prim,
			    uint8_t *data, size_t len);
int sgsn_ranap_iu_rx_co_initial_msg(struct sgsn_sccp_user_iups *scu_iups, const struct osmo_sccp_addr *rem_sccp_addr,
				    uint32_t conn_id, uint8_t *data, size_t len);
int sgsn_ranap_iu_rx_co_msg(struct ranap_ue_conn_ctx *ue_ctx, uint8_t *data, size_t len);

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
