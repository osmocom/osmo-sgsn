#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

struct msgb;

extern const struct tlv_definition gsm48_gmm_ie_tlvdef;

/* 9.4.14 RAU Request */
struct gprs_gmm_ra_upd_req {
	uint8_t skip_ind; /* 10.3.1 */
	uint8_t update_type; /* 10.5.5.18 */
	bool follow_up_req; /* 10.5.5.18 */
	uint8_t cksq; /* 10.5.1.2 */
	struct osmo_routing_area_id old_rai; /* 10.5.5.15 */
	uint8_t *ms_radio_cap; /* 10.5.5.12a */
	uint8_t ms_radio_cap_len;
	enum gsm48_ptsmi_type ptmsi_type;
	uint32_t ptmsi;
	struct tlv_parsed tlv;
};

int gprs_gmm_parse_ra_upd_req(struct msgb *msg, struct gprs_gmm_ra_upd_req *rau_req);
