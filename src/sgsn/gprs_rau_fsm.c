/* Routing Area Update FSM for MMCtx to synchrozie for foreign RAU to local RAU transistions */

/* (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Alexander Couzens <lynxis@fe80.eu>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/fsm.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/vlr/vlr.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_rau_fsm.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/signal.h>

#define S(x)	(1 << (x))

const struct value_string gmm_rau_event_names[] = {
	OSMO_VALUE_STRING(GMM_RAU_E_UE_RAU_REQUEST),
	OSMO_VALUE_STRING(GMM_RAU_E_VLR_RAU_ACCEPT),
	OSMO_VALUE_STRING(GMM_RAU_E_VLR_RAU_REJECT),
	OSMO_VALUE_STRING(GMM_RAU_E_GGSN_UPD_RESP),
	OSMO_VALUE_STRING(GMM_RAU_E_UE_RAU_COMPLETE),
	OSMO_VALUE_STRING(GMM_RAU_E_VLR_TERM_FAIL),
	OSMO_VALUE_STRING(GMM_RAU_E_VLR_TERM_SUCCESS),
	{ 0, NULL }
};

struct osmo_tdef_state_timeout gmm_rau_tdef_states[32] = {
};

struct osmo_tdef gmm_rau_tdefs[] = {
	// { .T = 3350, .default_val = 6, .desc = "Attach/RAU Complete Reallocation procedure" },
	{ /* terminator */ }
};

/* Terminate reason, used by osmo_fsm_term as data */
char *fsm_term_rau_att_req    = "Attach Req Rx while in RAU";
char *fsm_term_att_req_chg    = "Attach Req Changed";
char *fsm_term_att_rej        = "Attach Rej";
char *fsm_term_att_success    = "Attach Success";
char *fsm_term_rau_req_chg    = "RAU Req Changed";
char *fsm_term_rau_rej        = "RAU Rej";
char *fsm_term_rau_success    = "RAU Success";

static inline struct sgsn_mm_ctx *gmm_rau_fsm_priv(struct osmo_fsm_inst *fi)
{
	return (struct sgsn_mm_ctx *) fi->priv;
}


static void gmm_rau_fsm_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *mmctx = gmm_rau_fsm_priv(fi);

	switch (event) {
	case GMM_RAU_E_UE_RAU_REQUEST:
		mmctx->vsub->lu_fsm = vlr_ra_update(
		    mmctx->attach_rau.rau_fsm, GMM_RAU_E_VLR_TERM_SUCCESS, GMM_RAU_E_VLR_TERM_FAIL, NULL,
		    sgsn->vlr,
		    mmctx,
		    mmctx->attach_rau.rau_type,
		    mmctx->p_tmsi,
		    mmctx->imsi,
		    &mmctx->attach_rau.old_rai,
		    &mmctx->ra,
		    sgsn->cfg.auth_policy == SGSN_AUTH_POLICY_REMOTE,
		    mmctx->ciph_algo != GPRS_ALGO_GEA0,
		    mmctx->ciph_algo != GPRS_ALGO_GEA0,
		    mmctx->attach_rau.cksq,
		    sgsn_mm_ctx_is_r99(mmctx),
		    mmctx->ran_type == MM_CTX_T_UTRAN_Iu,
		    true);

		osmo_tdef_fsm_inst_state_chg(fi, GMM_RAU_S_WAIT_VLR_ANSWER, gmm_rau_tdef_states, gmm_rau_tdefs, 0);
		osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_COMMON_PROC_INIT_REQ, NULL);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void transmit_rau_accept(struct sgsn_mm_ctx *mmctx)
{
	switch (mmctx->attach_rau.rau_type) {
	case VLR_LU_TYPE_PERIODIC:
	case VLR_LU_TYPE_REGULAR:
		gsm48_tx_gmm_ra_upd_ack(mmctx);
		break;
	case VLR_LU_TYPE_IMSI_ATTACH:
		gsm48_tx_gmm_att_ack(mmctx);
		break;
	}

}

static void transmit_rau_reject(struct sgsn_mm_ctx *mmctx, uint8_t gmm_cause)
{
	if (gmm_cause == 0)
		gmm_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;

	switch (mmctx->attach_rau.rau_type) {
	case VLR_LU_TYPE_PERIODIC:
	case VLR_LU_TYPE_REGULAR:
		gsm48_tx_gmm_ra_upd_rej(mmctx, gmm_cause);
		break;
	case VLR_LU_TYPE_IMSI_ATTACH:
		gsm48_tx_gmm_att_rej(mmctx, gmm_cause);
		break;
	default:
		OSMO_ASSERT(0);
	}
}

static void gmm_rau_fsm_s_wait_vlr(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *mmctx = gmm_rau_fsm_priv(fi);
	uint8_t gmm_cause;

	switch (event) {
	case GMM_RAU_E_UE_RAU_REQUEST:
		/* same RAU, a different RAU would terminate this FSM */
		break;
	case GMM_RAU_E_VLR_RAU_ACCEPT:
		/* delay forwarding it */
		if (mmctx->attach_rau.foreign) {
			osmo_tdef_fsm_inst_state_chg(fi, GMM_RAU_S_WAIT_GGSN_UPDATE, gmm_rau_tdef_states, gmm_rau_tdefs, 0);
		} else {
			transmit_rau_accept(mmctx);
			osmo_tdef_fsm_inst_state_chg(fi, GMM_RAU_S_WAIT_UE_RAU_COMPLETE, gmm_rau_tdef_states, gmm_rau_tdefs, 0);
		}
		break;
	case GMM_RAU_E_VLR_RAU_REJECT:
		gmm_cause = (uint8_t) ((long) data & 0xff);
		transmit_rau_reject(mmctx, gmm_cause);
		break;
	case GMM_RAU_E_VLR_TERM_FAIL:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, data);
		break;
	case GMM_RAU_E_VLR_TERM_SUCCESS:
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void transmit_update_pdp_req(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_pdp_ctx *pctx;

	/* When receiving PDP context via Gn, all PDP context must taken cared off:
	 * if the UE still knows about them, update the GTP path
	 * or termiante the PDP context, when the UE states this has been dropped. */
	llist_for_each_entry(pctx, &mmctx->pdp_list, list) {
		if (pctx->ue_pdp_active)
			sgsn_pdp_ctx_gn_update(pctx);
		else
			sgsn_pdp_ctx_terminate(pctx);
	}
}

void gmm_rau_fsm_s_wait_ggsn_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *mmctx = gmm_rau_fsm_priv(fi);
	/* transmit Update PDP Request when doing a Inter-SGSN handover (or 4G->2G/4G) */

	/* FIXME: move Gn into a FSM and wait for a response before sending out the RAU Accept */
	/* update the PDP Request should be done now */
	transmit_update_pdp_req(mmctx);
}

static void gmm_rau_fsm_s_wait_ggsn(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *mmctx = gmm_rau_fsm_priv(fi);

	switch (event) {
	case GMM_RAU_E_GGSN_UPD_RESP:
		transmit_rau_accept(mmctx);
		// FIXME: transmit Routing Area Update Accpet OR inform the VLR to continue ULA */
		/* FIXME: check for *all* pdp before going to next state */
		osmo_tdef_fsm_inst_state_chg(fi, GMM_RAU_S_WAIT_UE_RAU_COMPLETE, gmm_rau_tdef_states, gmm_rau_tdefs, 0);
		break;
	case GMM_RAU_E_VLR_RAU_REJECT:
		/* FIXME */
		break;
	case GMM_RAU_E_UE_RAU_REQUEST:
		/* same RAU, a different RAU would terminate this FSM */
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}

static void gmm_rau_fsm_s_wait_ue_rau_compl(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *mmctx = gmm_rau_fsm_priv(fi);
	uint8_t cause;

	switch (event) {
	case GMM_RAU_E_UE_RAU_COMPLETE:
		/* inform the VLR */
		if (mmctx->vsub)
			vlr_subscr_rx_rau_complete(mmctx->vsub);

		/* We need to wait for the VLR/LU FSM to terminate */
		break;
	case GMM_RAU_E_VLR_TERM_SUCCESS:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case GMM_RAU_E_VLR_TERM_FAIL:
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		break;
	case GMM_RAU_E_VLR_RAU_REJECT:
		/* VLR timed out */
		cause = ((long) data) & 0xff;
		transmit_rau_reject(mmctx, cause);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, data);
		break;
	case GMM_RAU_E_VLR_RAU_ACCEPT:
	case GMM_RAU_E_UE_RAU_REQUEST:
		transmit_rau_accept(mmctx);
		break;
	default:
		OSMO_ASSERT(0);
		break;
	}
}
static void gmm_attach_success(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_signal_data sig_data;

	switch(mmctx->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
		osmo_fsm_inst_dispatch(mmctx->iu.mm_state_fsm, E_PMM_PS_ATTACH, NULL);
		break;
	case MM_CTX_T_GERAN_Gb:
		/* Unassign the old TLLI */
		mmctx->gb.tlli = mmctx->gb.tlli_new;
		gprs_llme_copy_key(mmctx, mmctx->gb.llme);
		gprs_llgmm_assign(mmctx->gb.llme, TLLI_UNASSIGNED,
				  mmctx->gb.tlli_new);
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_GPRS_ATTACH, NULL);
		break;
	}

	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_ATTACH_SUCCESS, NULL);

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_ATTACH, &sig_data);
}

static void gmm_rau_success(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_signal_data sig_data;

	switch(mmctx->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
		osmo_fsm_inst_dispatch(mmctx->iu.mm_state_fsm, E_PMM_RA_UPDATE, NULL);
		break;
	case MM_CTX_T_GERAN_Gb:
		/* Unassign the old TLLI */
		mmctx->gb.tlli = mmctx->gb.tlli_new;
		gprs_llgmm_assign(mmctx->gb.llme, TLLI_UNASSIGNED, mmctx->gb.tlli_new);
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_RA_UPDATE, NULL);
		break;
	}

	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_RAU_SUCCESS, NULL);

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_UPDATE, &sig_data);
}

static void gmm_rau_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct sgsn_mm_ctx *mmctx;
	uint32_t event;

	/* deregister ourselfs from MMCtx */
	if (!fi->priv)
		return;

	mmctx = gmm_rau_fsm_priv(fi);
	mmctx->attach_rau.rau_fsm = NULL;
	fi->priv = NULL;

	switch (cause) {
	case OSMO_FSM_TERM_REGULAR:
		/* Successful Attach or RAU */
		switch (mmctx->attach_rau.rau_type) {
		case VLR_LU_TYPE_IMSI_ATTACH:
			gmm_attach_success(mmctx);
			break;
		case VLR_LU_TYPE_REGULAR:
		case VLR_LU_TYPE_PERIODIC:
			gmm_rau_success(mmctx);
			break;
		}

		break;
	case OSMO_FSM_TERM_ERROR:
	case OSMO_FSM_TERM_TIMEOUT:
		event = E_GMM_COMMON_PROC_FAILED;
		if (mmctx->attach_rau.rau_type == VLR_LU_TYPE_IMSI_ATTACH)
			event = E_GMM_ATTACH_FAILED;

		osmo_fsm_inst_dispatch(mmctx->gmm_fsm, event, NULL);
		break;
	case OSMO_FSM_TERM_REQUEST:
		/* Called when another Att/Rau Request received with different context, silenty terminate and wait for re-creation */
		break;
	default:
		break;
	}

	TALLOC_FREE(mmctx->attach_rau.req);
	memset(&mmctx->attach_rau, 0, sizeof(mmctx->attach_rau));
}

static const struct osmo_fsm_state gmm_rau_fsm_states[] = {
	[GMM_RAU_S_INIT] = {
		.in_event_mask = S(GMM_RAU_E_UE_RAU_REQUEST),
		.out_state_mask = S(GMM_RAU_S_WAIT_VLR_ANSWER),
		.name = OSMO_STRINGIFY(GMM_RAU_S_INIT),
		.action = gmm_rau_fsm_s_init,
	},
	[GMM_RAU_S_WAIT_VLR_ANSWER] = {
		.in_event_mask = S(GMM_RAU_E_UE_RAU_REQUEST) | S(GMM_RAU_E_VLR_RAU_ACCEPT) | S(GMM_RAU_E_VLR_RAU_REJECT) | S(GMM_RAU_E_VLR_TERM_SUCCESS)| S(GMM_RAU_E_VLR_TERM_FAIL),
		.out_state_mask = S(GMM_RAU_S_WAIT_GGSN_UPDATE) |
			S(GMM_RAU_S_WAIT_UE_RAU_COMPLETE),
		.name = OSMO_STRINGIFY(GMM_RAU_S_WAIT_VLR_ANSWER),
		.action = gmm_rau_fsm_s_wait_vlr,
	},
	[GMM_RAU_S_WAIT_GGSN_UPDATE] = {
		.in_event_mask = S(GMM_RAU_E_UE_RAU_REQUEST) | S(GMM_RAU_E_GGSN_UPD_RESP) | S(GMM_RAU_E_VLR_RAU_REJECT) | S(GMM_RAU_E_VLR_TERM_SUCCESS)| S(GMM_RAU_E_VLR_TERM_FAIL),
		.out_state_mask = S(GMM_RAU_S_WAIT_UE_RAU_COMPLETE),
		.name = OSMO_STRINGIFY(GMM_RAU_S_WAIT_GGSN_UPDATE),
		.action = gmm_rau_fsm_s_wait_ggsn,
		.onenter = gmm_rau_fsm_s_wait_ggsn_onenter,
	},
	/* FIXME: add PVLR step here as well? */
	[GMM_RAU_S_WAIT_UE_RAU_COMPLETE] = {
		.in_event_mask = S(GMM_RAU_E_UE_RAU_COMPLETE) | S(GMM_RAU_E_VLR_RAU_REJECT) | S(GMM_RAU_E_VLR_RAU_ACCEPT) | S(GMM_RAU_E_UE_RAU_REQUEST) | S(GMM_RAU_E_VLR_TERM_SUCCESS)| S(GMM_RAU_E_VLR_TERM_FAIL),
		.out_state_mask = 0,
		.name = OSMO_STRINGIFY(GMM_RAU_S_WAIT_UE_RAU_COMPLETE),
		.action = gmm_rau_fsm_s_wait_ue_rau_compl,
	},
};

static struct osmo_fsm gmm_rau_fsm = {
	.name = "gmm_rau_fsm",
	.states = gmm_rau_fsm_states,
	.num_states = ARRAY_SIZE(gmm_rau_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DLGLOBAL,
	.event_names = gmm_rau_event_names,
	.cleanup = gmm_rau_fsm_cleanup,
	.pre_term = NULL,
	.timer_cb = NULL,
};

void gmm_rau_fsm_req(struct sgsn_mm_ctx *mmctx)
{
	OSMO_ASSERT(!mmctx->attach_rau.rau_fsm);

	mmctx->attach_rau.rau_fsm = osmo_fsm_inst_alloc(&gmm_rau_fsm, mmctx, mmctx, LOGL_INFO, NULL);

	osmo_fsm_inst_dispatch(mmctx->attach_rau.rau_fsm, GMM_RAU_E_UE_RAU_REQUEST, NULL);
}

static __attribute__((constructor)) void gmm_rau_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&gmm_rau_fsm) == 0);
}
