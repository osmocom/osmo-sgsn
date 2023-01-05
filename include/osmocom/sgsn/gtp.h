#pragma once

struct sgsn_instance;

int sgsn_gtp_init(struct sgsn_instance *sgi);

int sgsn_gtp_data_req(struct gprs_ra_id *ra_id, int32_t tlli, uint8_t nsapi,
		      struct msgb *msg, uint32_t npdu_len, uint8_t *npdu);
