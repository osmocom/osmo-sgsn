#include <stdint.h>

#include <osmocom/core/fsm.h>

#include <osmocom/ranap/ranap_ies_defs.h>

struct ranap_iu_rnc;

enum iu_rnc_state {
	IU_RNC_ST_WAIT_RX_RESET = 0,
	IU_RNC_ST_WAIT_RX_RESET_ACK,
	IU_RNC_ST_READY,
	IU_RNC_ST_DISCARDING,
};

struct iu_rnc_ev_msg_up_co_initial_ctx {
	struct ranap_iu_rnc *rnc;
	uint32_t conn_id;
	ranap_message message;
};

struct iu_rnc_ev_msg_up_co_ctx {
	struct ranap_ue_conn_ctx *ue_ctx;
	ranap_message message;
};

enum iu_rnc_event {
	IU_RNC_EV_MSG_UP_CO_INITIAL, /* struct iu_rnc_ev_msg_up_co_initial_ctx* */
	IU_RNC_EV_MSG_UP_CO, /* struct iu_rnc_ev_msg_up_co_ctx* */
	IU_RNC_EV_RX_RESET, /* no param */
	IU_RNC_EV_RX_RESET_ACK, /* no param */
	IU_RNC_EV_MSG_DOWN_CL, /* struct msgb* */
	IU_RNC_EV_AVAILABLE,
	IU_RNC_EV_UNAVAILABLE
};

extern struct osmo_fsm iu_rnc_fsm;
