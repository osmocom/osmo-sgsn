#pragma once

#include <osmocom/core/fsm.h>

struct sgsn_mm_ctx;


/* TS 23.060 § 6.1.1 Mobility Management States (A/Gb mode) */
enum mm_state_gb_fsm_states {
	ST_MM_IDLE,
	ST_MM_READY,
	ST_MM_STANDBY
};

enum mm_state_gb_fsm_events {
	E_MM_GPRS_ATTACH,
	E_MM_GPRS_DETACH,  /* MS becomes detached: due to Detach Req, RAU reject, implicit detach, etc. */
	E_MM_PDU_RECEPTION,
	E_MM_READY_TIMER_EXPIRY,
	/* E_FORCE_TO_STANDBY, TODO: not used */
	/* E_ABNSORMAL_RLC_CONDITION, TODO: not used */
	E_MM_RA_UPDATE,
};

extern struct osmo_fsm mm_state_gb_fsm;
