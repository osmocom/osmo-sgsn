#include <arpa/inet.h>

#include <osmocom/core/tdef.h>

#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_ranap.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout mm_state_iu_fsm_timeouts[32] = {
	[ST_PMM_DETACHED] = { },
	/* non-spec -T3314 (User inactivity timer) */
	[ST_PMM_CONNECTED] = { .T=-3314 },
	[ST_PMM_IDLE] = { },
};

#define mm_state_iu_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, mm_state_iu_fsm_timeouts, sgsn->cfg.T_defs, -1)

static void mmctx_change_gtpu_endpoints_to_sgsn(struct sgsn_mm_ctx *mm_ctx)
{
	char buf[INET_ADDRSTRLEN];
	struct sgsn_pdp_ctx *pdp;
	llist_for_each_entry(pdp, &mm_ctx->pdp_list, list) {
		LOGMMCTXP(LOGL_INFO, mm_ctx, "Changing GTP-U endpoints %s -> %s\n",
			  sgsn_gtp_ntoa(&pdp->lib->gsnlu),
			  inet_ntop(AF_INET, &sgsn->cfg.gtp_listenaddr.sin_addr, buf, sizeof(buf)));
		sgsn_pdp_upd_gtp_u(pdp,
				   &sgsn->cfg.gtp_listenaddr.sin_addr,
				   sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));
	}
}

static void st_pmm_detached(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_PMM_PS_ATTACH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_CONNECTED);
		break;
	case E_PMM_IMPLICIT_DETACH:
		break;
	}
}

static void st_pmm_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	const struct RANAP_Cause user_inactive_cause = {
		.present = RANAP_Cause_PR_radioNetwork,
		.choice.radioNetwork = RANAP_CauseRadioNetwork_user_inactivity,
	};

	switch(event) {
	case E_PMM_PS_CONN_RELEASE:
		sgsn_ranap_iu_free(ctx);
		mm_state_iu_fsm_state_chg(fi, ST_PMM_IDLE);
		break;
	case E_PMM_IMPLICIT_DETACH:
		sgsn_ranap_iu_release_free(ctx, NULL);
		mm_state_iu_fsm_state_chg(fi, ST_PMM_DETACHED);
		break;
	case E_PMM_USER_INACTIVITY:
		sgsn_ranap_iu_release_free(ctx, &user_inactive_cause);
		break;
	case E_PMM_RA_UPDATE:
		break;
	}
}

static void st_pmm_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	mmctx_change_gtpu_endpoints_to_sgsn(ctx);
}

static void st_pmm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_PMM_PS_ATTACH:
	case E_PMM_PS_CONN_ESTABLISH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_CONNECTED);
		break;
	case E_PMM_IMPLICIT_DETACH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_DETACHED);
		break;
	}
}

static int pmm_state_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch(fi->state) {
	case ST_PMM_CONNECTED:
		/* timer for pmm state. state=CONNECTED: -T3314 (User inactivity timer) */
		osmo_fsm_inst_dispatch(fi, E_PMM_USER_INACTIVITY, NULL);
		break;
	}

	return 0;
}

static struct osmo_fsm_state mm_state_iu_fsm_states[] = {
	[ST_PMM_DETACHED] = {
		.in_event_mask = X(E_PMM_PS_ATTACH) | X(E_PMM_IMPLICIT_DETACH),
		.out_state_mask = X(ST_PMM_CONNECTED),
		.name = "Detached",
		.action = st_pmm_detached,
	},
	[ST_PMM_CONNECTED] = {
		.in_event_mask = X(E_PMM_PS_CONN_RELEASE) | X(E_PMM_RA_UPDATE)
			| X(E_PMM_IMPLICIT_DETACH) | X(E_PMM_USER_INACTIVITY),
		.out_state_mask = X(ST_PMM_DETACHED) | X(ST_PMM_IDLE),
		.name = "Connected",
		.action = st_pmm_connected,
	},
	[ST_PMM_IDLE] = {
		.in_event_mask =
			X(E_PMM_IMPLICIT_DETACH) |
			X(E_PMM_PS_CONN_ESTABLISH) |
			X(E_PMM_PS_ATTACH),
		.out_state_mask = X(ST_PMM_DETACHED) | X(ST_PMM_CONNECTED),
		.name = "Idle",
		.onenter = st_pmm_idle_on_enter,
		.action = st_pmm_idle,
	},
};

const struct value_string mm_state_iu_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_PMM_PS_ATTACH),
	OSMO_VALUE_STRING(E_PMM_PS_CONN_RELEASE),
	OSMO_VALUE_STRING(E_PMM_PS_CONN_ESTABLISH),
	OSMO_VALUE_STRING(E_PMM_IMPLICIT_DETACH),
	OSMO_VALUE_STRING(E_PMM_RA_UPDATE),
	OSMO_VALUE_STRING(E_PMM_USER_INACTIVITY),
	{ 0, NULL }
};

struct osmo_fsm mm_state_iu_fsm = {
	.name = "MM_STATE_Iu",
	.states = mm_state_iu_fsm_states,
	.num_states = ARRAY_SIZE(mm_state_iu_fsm_states),
	.event_names = mm_state_iu_fsm_event_names,
	.timer_cb = pmm_state_fsm_timer_cb,
	.log_subsys = DMM,
};

static __attribute__((constructor)) void mm_state_iu_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&mm_state_iu_fsm) == 0);
}
