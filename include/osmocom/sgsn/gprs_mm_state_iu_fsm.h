#pragma once

#include <osmocom/core/fsm.h>

struct sgsn_mm_ctx;

/* TS 23.060 § 6.1.2 Mobility Management States (Iu mode) */
enum mm_state_iu_fsm_states {
	ST_PMM_DETACHED,
	ST_PMM_CONNECTED,
	ST_PMM_IDLE
};

enum mm_state_iu_fsm_events {
	E_PMM_PS_ATTACH,
	E_PMM_PS_DETACH, /* UE becomes detached: due to Detach Req, RAU reject, implicit detach, etc. */
	E_PMM_PS_CONN_RELEASE,
	E_PMM_PS_CONN_ESTABLISH,
	E_PMM_RA_UPDATE, /* = Serving RNC relocation */
};

extern struct osmo_fsm mm_state_iu_fsm;
