#ifndef GPRS_GMM_RAU_H
#define GPRS_GMM_RAU_H

#include <osmocom/core/fsm.h>

struct sgsn_mm_ctx;

enum gmm_rau_req_fsm_states {
	ST_INIT,
	ST_IDENTIY,
	ST_RETRIEVE_AUTH,
	ST_AUTH,
	ST_ASK_VLR,
	ST_IU_SECURITY_CMD,
	ST_ACCEPT,
	ST_REJECT
};

enum gmm_rau_req_fsm_events {
	E_RAU_REQ_RECV,
	E_IDEN_RESP_RECV,
	E_AUTH_RESP_RECV_SUCCESS,
	E_AUTH_RESP_RECV_RESYNC,
	E_IU_SECURITY_CMD_COMPLETE,
	E_RAU_ACCEPTED,
	E_RAU_ACCEPT_SENT,
	E_RAU_COMPLETE_RECV,
	E_REJECT,
	E_VLR_ANSWERED,
};

#define GMM_DISCARD_MS_WITHOUT_REJECT -1

extern const struct value_string gmm_rau_req_fsm_event_names[];
extern struct osmo_fsm gmm_rau_req_fsm;

void gmm_att_req_free(struct sgsn_mm_ctx *mm);

#endif // GPRS_GMM_RAU_H
