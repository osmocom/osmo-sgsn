#pragma once

#include <stddef.h>
#include <stdint.h>

#include <osmocom/core/socket.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>

#include <osmocom/gtp/pdp.h>

struct gprs_ra_id;
struct sgsn_instance;
struct sgsn_ggsn_ctx;
struct sgsn_pdp_ctx;
struct sgsn_mm_ctx;
struct sgsn_mme_ctx;
struct gsn_t;

int sgsn_gtp_init(struct sgsn_instance *sgi);

int sgsn_mme_ran_info_req(struct sgsn_mme_ctx *mme, const struct bssgp_ran_information_pdu *pdu);

void sgsn_ggsn_echo_req(struct sgsn_ggsn_ctx *ggc);
struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp);

int sgsn_gtp_data_req(struct osmo_routing_area_id *rai, int32_t tlli, uint8_t nsapi,
		      struct msgb *msg, uint32_t npdu_len, uint8_t *npdu);
int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx);
int send_act_pdp_cont_acc(struct sgsn_pdp_ctx *pctx);

static inline int gsna_to_osa(struct osmo_sockaddr *dst, const struct ul16_t *in)
{
	return osmo_sockaddr_from_octets(dst, &in->v[0], in->l);
}

int sgsn_context_ack(struct gsn_t *gsn, struct sgsn_mm_ctx *mmctx, uint8_t cause);
