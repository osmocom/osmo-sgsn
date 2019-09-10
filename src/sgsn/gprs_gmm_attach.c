#include <osmocom/core/tdef.h>

#include <osmocom/sgsn/gprs_gmm_attach.h>

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/sgsn.h>

#define X(s) (1 << (s))

static int require_identity_imei = 1;
static int require_auth = 1;

static const struct osmo_tdef_state_timeout gmm_attach_fsm_timeouts[32] = {
	[ST_IDENTIY] = { .T=3370 },
	[ST_AUTH] = { .T=3360 },
	[ST_ACCEPT] = { .T=3350 },
	[ST_ASK_VLR] = { .T=3350 },
	[ST_IU_SECURITY_CMD] = { .T=3350 },
};

#define gmm_attach_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, gmm_attach_fsm_timeouts, sgsn->cfg.T_defs, -1)


static void st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	struct msgb *attach_req = data;

	/* we can run st_init multiple times */
	if (ctx->gmm_att_req.attach_req)
		msgb_free(ctx->gmm_att_req.attach_req);

	ctx->gmm_att_req.attach_req = msgb_copy(attach_req, "Attach Request");
	ctx->auth_state = SGSN_AUTH_UNKNOWN;
	ctx->gmm_att_req.auth_reattempt = 0;

	/*
	 * TODO: remove pending_req as soon the sgsn_auth code doesn't depend
	 * on it.
	 * pending_req must be set, even this fsm doesn't use it, because
	 * the sgsn_auth code is using this too
	 */
	ctx->pending_req = GSM48_MT_GMM_ATTACH_REQ;

	if (require_identity_imei) {
		ctx->gmm_att_req.id_type = GSM_MI_TYPE_IMEI;
		gmm_attach_fsm_state_chg(fi, ST_IDENTIY);
	} else if (!strlen(ctx->imsi)) {
		ctx->gmm_att_req.id_type = GSM_MI_TYPE_IMSI;
		gmm_attach_fsm_state_chg(fi, ST_IDENTIY);
	} else if (require_auth)
		gmm_attach_fsm_state_chg(fi, ST_AUTH);
	else
		gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
}

static void st_identity_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	int ret = 0;

	ctx->num_T_exp = 0;

	switch (ctx->gmm_att_req.id_type) {
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMSI:
		break;
	default:
		/* TODO logging */
		osmo_fsm_inst_dispatch(fi, E_REJECT, NULL);
		return;
	}

	ctx->t3370_id_type = ctx->gmm_att_req.id_type;
	ret = gsm48_tx_gmm_id_req(ctx, ctx->gmm_att_req.id_type);
	if (ret < 0) {
		LOGPFSM(fi, "Can not send tx_gmm_id %d.\n", ret);
		osmo_fsm_inst_dispatch(fi, E_REJECT, NULL);
	}
}

static void st_identity(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	OSMO_ASSERT(event == E_IDEN_RESP_RECV);

	/* check if we received a identity response */
	long type = (long) data;
	switch (type) {
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMSI:
		break;
	default:
		LOGMMCTXP(LOGL_ERROR, ctx, "Unknown mi type: 0x%lx, rejecting MS.\n", type);
		osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_CAUSE_NET_FAIL);
		return;
	}

	if (type != ctx->gmm_att_req.id_type) {
		/* ignore wrong package */
		/* TODO logging */
		return;
	}

	if (type == GSM_MI_TYPE_IMEI && !strlen(ctx->imsi)) {
		ctx->gmm_att_req.id_type = GSM_MI_TYPE_IMSI;
		gmm_attach_fsm_state_chg(fi, ST_IDENTIY);
	} else if (require_auth)
		gmm_attach_fsm_state_chg(fi, ST_AUTH);
	else
		gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
}

static void st_auth_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	enum sgsn_auth_state auth_state;

	ctx->num_T_exp = 0;

	/* TODO: remove this layer violation. Don't parse any auth_policy here
	 * The correct way would be to ask the SGSN is this mmctx has to be auth
	 * regardless of the state.
	 * Otherwise someone else could steal the TLLI and just use it without further
	 * auth.
	 */
	if (sgsn->cfg.auth_policy != SGSN_AUTH_POLICY_REMOTE) {
		/* we can "trust" sgsn_auth_state as long it's not remote */
		auth_state = sgsn_auth_state(ctx);
	} else {
		auth_state = ctx->auth_state;
	}

	switch(auth_state) {
	case SGSN_AUTH_UMTS_RESYNC: /* ask the vlr for a new vector to match the simcards seq */
	case SGSN_AUTH_UNKNOWN: /* the SGSN doesn know this MS */
		gmm_attach_fsm_state_chg(fi, ST_ASK_VLR);
		break;
	case SGSN_AUTH_REJECTED:
		/* TODO: correct GMM cause */
		osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_CAUSE_GPRS_NOTALLOWED);
		break;
	case SGSN_AUTH_ACCEPTED:
		gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
		break;
	case SGSN_AUTH_AUTHENTICATE:
		if (ctx->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
			/* invalid key material */
			gmm_attach_fsm_state_chg(fi, ST_ASK_VLR);
		}

		struct gsm_auth_tuple *at = &ctx->auth_triplet;
		if (gsm48_tx_gmm_auth_ciph_req(ctx, &at->vec, at->key_seq,
					       false) < 0) {
			/* network failure */
			osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_CAUSE_NET_FAIL);
		}
		ctx->gmm_att_req.auth_reattempt++;
		break;
	}
}

static void st_auth(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	switch (event) {
	case E_AUTH_RESP_RECV_SUCCESS:
		if (sgsn_auth_needs_update_location(ctx)) {
			LOGMMCTXP(LOGL_INFO, ctx,
				  "Missing information, requesting subscriber data\n");
			gmm_attach_fsm_state_chg(fi, ST_WAIT_UPDATE_LOCATION);
		} else {
			gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
		}
		break;
	case E_AUTH_RESP_RECV_RESYNC:
		if (ctx->gmm_att_req.auth_reattempt <= 1)
			gmm_attach_fsm_state_chg(fi, ST_ASK_VLR);
		else
			osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_CAUSE_SYNC_FAIL);
		break;
	}
}

static void st_wait_lu_resp_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	int rc = gprs_subscr_request_update_location(ctx);
	if (rc < 0)
		LOGMMCTXP(LOGL_INFO, ctx, "Failed requesting Update Location\n");
}

static void st_wait_lu_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	switch (event) {
	case E_UPDATE_LOCATION_RESP_RECV_SUCCESS:
#ifdef BUILD_IU
		if (ctx->ran_type == MM_CTX_T_UTRAN_Iu && !ctx->iu.ue_ctx->integrity_active)
			gmm_attach_fsm_state_chg(fi, ST_IU_SECURITY_CMD);
		else
#endif /* BUILD_IU */
			gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
		break;
	}
}

static void st_accept_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	ctx->num_T_exp = 0;

	/* TODO: remove pending_req as soon the sgsn_auth code doesn't depend on it */
	ctx->pending_req = 0;
	gsm48_tx_gmm_att_ack(ctx);
}

static void st_accept(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	switch(event) {
	case E_ATTACH_COMPLETE_RECV:
		/* TODO: #ifdef ! PTMSI_ALLOC is not supported */
		extract_subscr_msisdn(ctx);
		extract_subscr_hlr(ctx);
		osmo_fsm_inst_state_chg(fi, ST_INIT, 0, 0);
		break;
	}
}

static void st_reject(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	long reject_cause = (long) data;

	if (reject_cause != GMM_DISCARD_MS_WITHOUT_REJECT)
		gsm48_tx_gmm_att_rej(ctx, (uint8_t) reject_cause);

	sgsn_mm_ctx_cleanup_free(ctx);
}

static void st_ask_vlr_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	/* FIXME: remove this layer violation.
	 * The VLR should send the message to the HLR and not the rx function
	 * gsm48_rx_gmm_auth_ciph_fail. Because gmm_auth_ciph_fail already send a
	 * message to the HLR, we don't send here a request. */
	if (ctx->auth_state == SGSN_AUTH_UMTS_RESYNC)
		return;

	/* ask the auth layer for more data */
	sgsn_auth_request(ctx);
}

static void st_ask_vlr(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_VLR_ANSWERED:
		gmm_attach_fsm_state_chg(fi, ST_AUTH);
		break;
	}
}

static void st_iu_security_cmd_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
#ifdef BUILD_IU
	struct sgsn_mm_ctx *ctx = fi->priv;

	/* TODO: shouldn't this set always? not only when the integrity_active? */
	if (ctx->iu.ue_ctx->integrity_active) {
		gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
		return;
	}

	ranap_iu_tx_sec_mode_cmd(ctx->iu.ue_ctx, &ctx->auth_triplet.vec, 0, ctx->iu.new_key);
	ctx->iu.new_key = 0;
#endif
}

static void st_iu_security_cmd(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_IU_SECURITY_CMD_COMPLETE:
		gmm_attach_fsm_state_chg(fi, ST_ACCEPT);
		break;
	}
}

static struct osmo_fsm_state gmm_attach_req_fsm_states[] = {
	/* default state for non-DTX and DTX when SPEECH is in progress */
	[ST_INIT] = {
		.in_event_mask = X(E_ATTACH_REQ_RECV),
		.out_state_mask = X(ST_INIT) | X(ST_IDENTIY) | X(ST_AUTH) | X(ST_ACCEPT),
		.name = "Init",
		.action = st_init,
	},
	[ST_ASK_VLR] = {
		.in_event_mask = X(E_VLR_ANSWERED),
		.out_state_mask = X(ST_INIT) | X(ST_AUTH) | X(ST_ACCEPT) | X(ST_REJECT),
		.name = "AskVLR",
		.onenter = st_ask_vlr_on_enter,
		.action = st_ask_vlr,
	},
	[ST_IDENTIY] = {
		.in_event_mask = X(E_IDEN_RESP_RECV),
		.out_state_mask = X(ST_INIT) | X(ST_AUTH) | X(ST_ACCEPT) | X(ST_IDENTIY) | X(ST_REJECT),
		.onenter = st_identity_on_enter,
		.name = "CheckIdentity",
		.action = st_identity,
	},
	[ST_AUTH] = {
		.in_event_mask = X(E_AUTH_RESP_RECV_SUCCESS) | X(E_AUTH_RESP_RECV_RESYNC),
		.out_state_mask = X(ST_INIT) | X(ST_AUTH) | X(ST_IU_SECURITY_CMD) | X(ST_ACCEPT) | X(ST_ASK_VLR) | X(ST_WAIT_UPDATE_LOCATION) | X(ST_REJECT),
		.name = "Authenticate",
		.onenter = st_auth_on_enter,
		.action = st_auth,
	},
	[ST_WAIT_UPDATE_LOCATION] = {
		.in_event_mask = X(E_UPDATE_LOCATION_RESP_RECV_SUCCESS),
		.out_state_mask = X(ST_INIT) | X(ST_ACCEPT) | X(ST_IU_SECURITY_CMD) | X(ST_REJECT),
		.name = "WaitLocationUpdateResp",
		.onenter = st_wait_lu_resp_on_enter,
		.action = st_wait_lu_resp,
	},
	[ST_IU_SECURITY_CMD] = {
		.in_event_mask = X(E_IU_SECURITY_CMD_COMPLETE),
		.out_state_mask = X(ST_INIT) | X(ST_AUTH) | X(ST_ACCEPT) | X(ST_REJECT),
		.name = "IuSecurityCommand",
		.onenter = st_iu_security_cmd_on_enter,
		.action = st_iu_security_cmd,
	},
	[ST_ACCEPT] = {
		.in_event_mask = X(E_ATTACH_COMPLETE_RECV),
		.out_state_mask = X(ST_INIT) | X(ST_REJECT),
		.name = "WaitAttachComplete",
		.onenter = st_accept_on_enter,
		.action = st_accept,
	},
	[ST_REJECT] = {
		.in_event_mask = X(E_REJECT),
		.out_state_mask = X(ST_INIT),
		.name = "Reject",
		.action = st_reject,
	},
};

const struct value_string gmm_attach_req_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_ATTACH_REQ_RECV),
	OSMO_VALUE_STRING(E_IDEN_RESP_RECV),
	OSMO_VALUE_STRING(E_AUTH_RESP_RECV_SUCCESS),
	OSMO_VALUE_STRING(E_AUTH_RESP_RECV_RESYNC),
	OSMO_VALUE_STRING(E_ATTACH_ACCEPTED),
	OSMO_VALUE_STRING(E_ATTACH_ACCEPT_SENT),
	OSMO_VALUE_STRING(E_ATTACH_COMPLETE_RECV),
	OSMO_VALUE_STRING(E_IU_SECURITY_CMD_COMPLETE),
	OSMO_VALUE_STRING(E_UPDATE_LOCATION_RESP_RECV_SUCCESS),
	OSMO_VALUE_STRING(E_REJECT),
	OSMO_VALUE_STRING(E_VLR_ANSWERED),
	{ 0, NULL }
};

void gmm_attach_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data) {
	struct sgsn_mm_ctx *ctx = fi->priv;
	struct msgb *new_attach_req = data;

	switch (event) {
	case E_ATTACH_REQ_RECV:
		switch (fi->state) {
		case ST_INIT:
		case ST_REJECT:
			st_init(fi, event, data);
			break;

		case ST_ACCEPT:
			/* TODO: drop all state (e.g. PDP Ctx) and do this procedure */
			osmo_fsm_inst_state_chg(fi, ST_INIT, 0, 0);
			st_init(fi, event, data);
			break;

		case ST_ASK_VLR:
		case ST_AUTH:
		case ST_IDENTIY:
		case ST_RETRIEVE_AUTH:
			/* 04.08 4.7.3.1.6 d) Abnormal Case
			 * Only do action if Req IEs differs. */
			if (ctx->gmm_att_req.attach_req &&
					gprs_gmm_attach_req_ies(new_attach_req, ctx->gmm_att_req.attach_req)) {
				osmo_fsm_inst_state_chg(fi, ST_INIT, 0, 0);
				st_init(fi, event, data);
			}
			break;
		}
		break;
	case E_REJECT:
		if (fi->state != ST_REJECT)
			osmo_fsm_inst_state_chg(fi, ST_REJECT, 0, 0);
		st_reject(fi, event, data);
		break;
	}
}

int gmm_attach_timer_cb(struct osmo_fsm_inst *fi)
{
	struct sgsn_mm_ctx *ctx = fi->priv;
	struct gsm_auth_tuple *at = &ctx->auth_triplet;
	unsigned long t_secs;

	ctx->num_T_exp++;

	switch(fi->state) {
	case ST_ASK_VLR:
		/* TODO: replace T3350 by a better timer or it's own
		 * re-use T3350 - not defined by standard */
		LOGMMCTXP(LOGL_ERROR, ctx, "HLR did not answer in time. Rejecting.\n");
		osmo_fsm_inst_dispatch(fi, E_REJECT,
				       (void *) GMM_CAUSE_NET_FAIL);
		break;
	case ST_IDENTIY:
		/* T3370 */
		if (ctx->num_T_exp >= 5) {
			osmo_fsm_inst_dispatch(fi, E_REJECT,
					       (void *) GMM_CAUSE_MS_ID_NOT_DERIVED);
			break;
		}
		gsm48_tx_gmm_id_req(ctx, ctx->gmm_att_req.id_type);
		t_secs = osmo_tdef_get(sgsn->cfg.T_defs, 3370, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, t_secs, 0);

		break;
	case ST_AUTH:
		/* T3360 */
		if (ctx->num_T_exp >= 5) {
			osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_DISCARD_MS_WITHOUT_REJECT);
			break;
		}
		gsm48_tx_gmm_auth_ciph_req(ctx, &at->vec, at->key_seq, false);
		t_secs = osmo_tdef_get(sgsn->cfg.T_defs, 3360, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, t_secs, 0);
		break;
	case ST_ACCEPT:
		/* T3350 */
		if (ctx->num_T_exp >= 5) {
			osmo_fsm_inst_dispatch(fi, E_REJECT, (void *) GMM_DISCARD_MS_WITHOUT_REJECT);
			break;
		}
		gsm48_tx_gmm_att_ack(ctx);
		t_secs = osmo_tdef_get(sgsn->cfg.T_defs, 3350, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, t_secs, 0);
		break;
	}

	return 0;
}

struct osmo_fsm gmm_attach_req_fsm = {
	.name = "GMM_ATTACH_REQ_FSM",
	.states = gmm_attach_req_fsm_states,
	.num_states = ARRAY_SIZE(gmm_attach_req_fsm_states),
	.event_names = gmm_attach_req_fsm_event_names,
	.allstate_event_mask = X(E_REJECT) | X(E_ATTACH_REQ_RECV),
	.allstate_action = gmm_attach_allstate_action,
	.log_subsys = DMM,
	.timer_cb = gmm_attach_timer_cb,
};

static __attribute__((constructor)) void gprs_gmm_fsm_init(void)
{
	osmo_fsm_register(&gmm_attach_req_fsm);
}

void gmm_att_req_free(struct sgsn_mm_ctx *mm) {
	if (mm->gmm_att_req.fsm)
		osmo_fsm_inst_free(mm->gmm_att_req.fsm);

	if (mm->gmm_att_req.attach_req)
		msgb_free(mm->gmm_att_req.attach_req);
}
