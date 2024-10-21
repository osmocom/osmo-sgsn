#pragma once

#include <osmocom/core/fsm.h>

#include <osmocom/sgsn/mmctx.h>

struct gprs_llc_llme;

/* 3GPP TS 24.008 § 4.1.3.3 GMM mobility management states on the network side */
enum gmm_fsm_states {
	ST_GMM_DEREGISTERED,		/* 4.1.3.3.1.1 */
	ST_GMM_COMMON_PROC_INIT,	/* 4.1.3.3.1.2 */
	ST_GMM_REGISTERED_NORMAL,	/* 4.1.3.3.2.1 */
	ST_GMM_REGISTERED_SUSPENDED,	/* 4.1.3.3.2.2 */
	ST_GMM_DEREGISTERED_INIT,	/* 4.1.3.3.1.4 */
};

enum gmm_fsm_events {
	E_GMM_COMMON_PROC_INIT_REQ,
	E_GMM_COMMON_PROC_FAILED,
	/* E_GMM_LOWER_LAYER_FAILED, NOT USED */
	E_GMM_COMMON_PROC_SUCCESS,
	E_GMM_ATTACH_SUCCESS,
	E_GMM_ATTACH_FAILED, /* Osmocom specific */
	E_GMM_RAU_SUCCESS,
	E_GMM_RAU_FAILED,
	E_GMM_NET_INIT_DETACH_REQ,
	E_GMM_MS_INIT_DETACH_REQ,
	E_GMM_DETACH_ACCEPTED,
	E_GMM_SUSPEND,
	E_GMM_RESUME,
	E_GMM_CLEANUP,
	E_GMM_RAT_CHANGE,
	E_GMM_SERVICE_ACCEPT, /* When a Service Request got accepted, Osmocom specific */
	E_GMM_SERVICE_REJECT, /* When a Service Request got rejected, Osmocom specific */
};

struct gmm_rat_change_data {
	enum sgsn_ran_type new_ran_type;
	struct gprs_llc_llme *llme;
};

static inline bool gmm_fsm_is_registered(struct osmo_fsm_inst *fi)
{
	return fi->state == ST_GMM_REGISTERED_NORMAL ||
	       fi->state == ST_GMM_REGISTERED_SUSPENDED;
}

extern struct osmo_fsm gmm_fsm;
