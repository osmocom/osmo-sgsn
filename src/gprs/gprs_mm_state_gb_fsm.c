#include <osmocom/core/tdef.h>

#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout mm_state_gb_fsm_timeouts[32] = {
	[ST_MM_IDLE] = { },
	[ST_MM_READY] = { .T=3314 },
	[ST_MM_STANDBY] = { },
};

#define mm_state_gb_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, mm_state_gb_fsm_timeouts, sgsn->cfg.T_defs, -1)

static void st_mm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_MM_GPRS_ATTACH:
		mm_state_gb_fsm_state_chg(fi, ST_MM_READY);
		break;
	case E_MM_PDU_RECEPTION:
		break;
	}
}

static void st_mm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	unsigned long t_secs;

	switch(event) {
	case E_MM_READY_TIMER_EXPIRY:
	case E_MM_IMPLICIT_DETACH:
		mm_state_gb_fsm_state_chg(fi, ST_MM_STANDBY);
		break;
	case E_MM_PDU_RECEPTION:
		/* RE-arm the READY timer upon receival of Gb PDUs */
		t_secs = osmo_tdef_get(sgsn->cfg.T_defs, 3314, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, t_secs, 0);
		break;
	case E_MM_RA_UPDATE:
		break;
	}
}

static void st_mm_standby(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_MM_PDU_RECEPTION:
		mm_state_gb_fsm_state_chg(fi, ST_MM_READY);
		break;
	}
}

static struct osmo_fsm_state mm_state_gb_fsm_states[] = {
	[ST_MM_IDLE] = {
		.in_event_mask = X(E_MM_GPRS_ATTACH) | X(E_MM_PDU_RECEPTION),
		.out_state_mask = X(ST_MM_READY),
		.name = "Idle",
		.action = st_mm_idle,
	},
	[ST_MM_READY] = {
		.in_event_mask = X(E_MM_READY_TIMER_EXPIRY) | X(E_MM_RA_UPDATE) | X(E_MM_IMPLICIT_DETACH) | X(E_MM_PDU_RECEPTION),
		.out_state_mask = X(ST_MM_IDLE) | X(ST_MM_STANDBY),
		.name = "Ready",
		.action = st_mm_ready,
	},
	[ST_MM_STANDBY] = {
		.in_event_mask = X(E_MM_PDU_RECEPTION),
		.out_state_mask = X(ST_MM_IDLE) | X(ST_MM_READY),
		.name = "Standby",
		.action = st_mm_standby,
	},
};

const struct value_string mm_state_gb_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_MM_GPRS_ATTACH),
	OSMO_VALUE_STRING(E_MM_PDU_RECEPTION),
	OSMO_VALUE_STRING(E_MM_IMPLICIT_DETACH),
	OSMO_VALUE_STRING(E_MM_READY_TIMER_EXPIRY),
	OSMO_VALUE_STRING(E_MM_RA_UPDATE),
	{ 0, NULL }
};

int mm_state_gb_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch(fi->state) {
	case ST_MM_READY:
		/* timer for mm state. state=READY: T3314 (aka TS 23.060 "READY timer") */
		osmo_fsm_inst_dispatch(fi, E_MM_READY_TIMER_EXPIRY, NULL);
		break;
	}

	return 0;
}

struct osmo_fsm mm_state_gb_fsm = {
	.name = "MM_STATE_Gb",
	.states = mm_state_gb_fsm_states,
	.num_states = ARRAY_SIZE(mm_state_gb_fsm_states),
	.event_names = mm_state_gb_fsm_event_names,
	.log_subsys = DMM,
	.timer_cb = mm_state_gb_fsm_timer_cb,
};

static __attribute__((constructor)) void mm_state_gb_fsm_init(void)
{
	osmo_fsm_register(&mm_state_gb_fsm);
}
