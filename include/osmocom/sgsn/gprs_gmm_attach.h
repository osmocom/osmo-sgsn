#ifndef GPRS_GMM_ATTACH_H
#define GPRS_GMM_ATTACH_H

#include <osmocom/core/fsm.h>

struct sgsn_mm_ctx;

enum gmm_attach_req_fsm_states {
	ST_INIT,
	ST_IDENTIY,
	ST_RETRIEVE_AUTH,
	ST_AUTH,
	ST_ASK_VLR,
	ST_ACCEPT,
	ST_REJECT
};

enum gmm_attach_req_fsm_events {
	E_ATTACH_REQ_RECV,
	E_IDEN_RESP_RECV,
	E_AUTH_RESP_RECV_SUCCESS,
	E_AUTH_RESP_RECV_RESYNC,
	E_ATTACH_ACCEPTED,
	E_ATTACH_ACCEPT_SENT,
	E_ATTACH_COMPLETE_RECV,
	E_REJECT,
	E_VLR_ANSWERED,
};

#define GMM_DISCARD_MS_WITHOUT_REJECT -1

extern const struct value_string gmm_attach_req_fsm_event_names[];
extern struct osmo_fsm gmm_attach_req_fsm;

void gmm_att_req_free(struct sgsn_mm_ctx *mm);

#endif // GPRS_GMM_ATTACH_H
