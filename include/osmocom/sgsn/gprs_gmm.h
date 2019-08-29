#ifndef _GPRS_GMM_H
#define _GPRS_GMM_H

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_sgsn.h>

#include <stdbool.h>

int gsm48_tx_gsm_deact_pdp_req(struct sgsn_pdp_ctx *pdp, uint8_t sm_cause, bool teardown);
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v);
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp);
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp);
int gsm48_tx_gmm_auth_ciph_req(struct sgsn_mm_ctx *mm,
				      const struct osmo_auth_vector *vec,
				      uint8_t key_seq, bool force_standby);

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
int gsm0408_rcv_gsm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme);
int gsm0408_rcv_gmm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme, bool drop_cipherable);
int gsm0408_gprs_force_reattach(struct sgsn_mm_ctx *mmctx);
int gsm0408_gprs_force_reattach_oldmsg(struct msgb *msg,
				       struct gprs_llc_llme *llme);
void gsm0408_gprs_access_granted(struct sgsn_mm_ctx *mmctx);
void gsm0408_gprs_access_denied(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_access_cancelled(struct sgsn_mm_ctx *mmctx, int gmm_cause);
void gsm0408_gprs_authenticate(struct sgsn_mm_ctx *mmctx);

int gprs_gmm_rx_suspend(struct gprs_ra_id *raid, uint32_t tlli);
int gprs_gmm_rx_resume(struct gprs_ra_id *raid, uint32_t tlli,
		       uint8_t suspend_ref);

time_t gprs_max_time_to_idle(void);

int gsm48_tx_gmm_id_req(struct sgsn_mm_ctx *mm, uint8_t id_type);
int gsm48_tx_gmm_att_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause);
int gsm48_tx_gmm_att_ack(struct sgsn_mm_ctx *mm);

int gprs_gmm_attach_req_ies(struct msgb *a, struct msgb *b);

int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx);
/* TODO: move extract_subscr_* when gsm48_gmm_authorize() got removed */
void extract_subscr_msisdn(struct sgsn_mm_ctx *ctx);
void extract_subscr_hlr(struct sgsn_mm_ctx *ctx);

void pdp_ctx_detach_mm_ctx(struct sgsn_pdp_ctx *pdp);

void mmctx_set_pmm_state(struct sgsn_mm_ctx *ctx, enum gprs_pmm_state state);
void mmctx_state_timer_start(struct sgsn_mm_ctx *mm, unsigned int T);
void mmctx_set_mm_state(struct sgsn_mm_ctx *ctx, enum gprs_pmm_state state);

void msgid2mmctx(struct sgsn_mm_ctx *mm, const struct msgb *msg);
#endif /* _GPRS_GMM_H */
