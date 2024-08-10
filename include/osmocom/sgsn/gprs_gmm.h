#ifndef _GPRS_GMM_H
#define _GPRS_GMM_H

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/crypt/auth.h>

struct sgsn_mm_ctx;
struct gprs_llc_llme;
struct osmo_routing_area_id;

int gsm48_tx_gmm_auth_ciph_req(struct sgsn_mm_ctx *mm,
				      const struct osmo_auth_vector *vec,
				      uint8_t key_seq, bool force_standby);

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
int gsm0408_rcv_gmm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme, bool drop_cipherable);
int gsm48_gmm_sendmsg(struct msgb *msg, int command,
			     struct sgsn_mm_ctx *mm, bool encryptable);
int gsm0408_gprs_force_reattach(struct sgsn_mm_ctx *mmctx);
int gsm0408_gprs_force_reattach_oldmsg(struct msgb *msg,
				       struct gprs_llc_llme *llme);
void gsm0408_gprs_access_granted(struct sgsn_mm_ctx *mmctx);
void gsm0408_gprs_access_denied(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_access_cancelled(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_authenticate(struct sgsn_mm_ctx *mmctx);

int gprs_gmm_rx_suspend(struct osmo_routing_area_id *raid, uint32_t tlli);
int gprs_gmm_rx_resume(struct osmo_routing_area_id *raid, uint32_t tlli,
		       uint8_t suspend_ref);

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
/* Has to be called whenever any PDU (signaling, data, ...) has been received */
void gprs_gb_recv_pdu(struct sgsn_mm_ctx *mmctx, const struct msgb *msg);

time_t gprs_max_time_to_idle(void);

int gsm48_tx_gmm_id_req(struct sgsn_mm_ctx *mm, uint8_t id_type);
int gsm48_tx_gmm_att_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause);
int gsm48_tx_gmm_att_ack(struct sgsn_mm_ctx *mm);

int gprs_gmm_msg_cmp(struct msgb *a, struct msgb *b);

int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx);
/* TODO: move extract_subscr_* when gsm48_gmm_authorize() got removed */
void extract_subscr_msisdn(struct sgsn_mm_ctx *ctx);
void extract_subscr_hlr(struct sgsn_mm_ctx *ctx);

void msgid2mmctx(struct sgsn_mm_ctx *mm, const struct msgb *msg);
void mmctx2msgid(struct msgb *msg, const struct sgsn_mm_ctx *mm);
#endif /* _GPRS_GMM_H */
