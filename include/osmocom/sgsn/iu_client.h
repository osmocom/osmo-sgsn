#pragma once

#include <stdbool.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/iuh/common.h>
#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/vty.h>
#include <osmocom/sigtran/sccp_sap.h>

struct msgb;
struct osmo_auth_vector;

struct RANAP_RAB_SetupOrModifiedItemIEs_s;
struct RANAP_Cause;

struct ranap_iu_rnc;

struct ranap_ue_conn_ctx {
	struct llist_head list;
	struct ranap_iu_rnc *rnc;
	uint32_t conn_id;
	int integrity_active;
	struct gprs_ra_id ra_id;
	enum ranap_nsap_addr_enc rab_assign_addr_enc;
	bool notification; /* send notification to the upstream user */
	/* if true the ue_ctx will be free on Iu release complete */
	bool free_on_release;
	/* Will be set when the Iu Release Command has been sent */
	struct osmo_timer_list release_timeout;
};

enum ranap_iu_event_new_area_type {
	RANAP_IU_NEW_LAC,
	RANAP_IU_NEW_RAC,
};

struct ranap_iu_event_new_area {
	const struct osmo_rnc_id *rnc_id;
	enum ranap_iu_event_new_area_type cell_type;
	union {
		const struct osmo_location_area_id *lai;
		const struct osmo_routing_area_id *rai;
	} u;
};

enum ranap_iu_event_type {
	RANAP_IU_EVENT_RAB_ASSIGN,
	RANAP_IU_EVENT_SECURITY_MODE_COMPLETE,
	RANAP_IU_EVENT_IU_RELEASE, /* An actual Iu Release message was received */
	RANAP_IU_EVENT_LINK_INVALIDATED, /* A SUA link was lost or closed down */
	RANAP_IU_EVENT_NEW_AREA, /* Either a new LAC/RAC has been detected */
};

extern const struct value_string ranap_iu_event_type_names[];
static inline const char *ranap_iu_event_type_str(enum ranap_iu_event_type e)
{
	return get_value_string(ranap_iu_event_type_names, e);
}

/* Implementations of iu_recv_cb_t shall find the ranap_ue_conn_ctx in msg->dst. */
typedef int (*ranap_iu_recv_cb_t)(struct msgb *msg, struct gprs_ra_id *ra_id,
				  uint16_t *sai);

typedef int (*ranap_iu_event_cb_t)(struct ranap_ue_conn_ctx *ue_ctx,
				   enum ranap_iu_event_type type, void *data);

typedef int (*ranap_iu_rab_ass_resp_cb_t)(struct ranap_ue_conn_ctx *ue_ctx, uint8_t rab_id,
					  struct RANAP_RAB_SetupOrModifiedItemIEs_s *setup_ies);

int ranap_iu_init(void *ctx, int log_subsystem, const char *sccp_user_name, struct osmo_sccp_instance *sccp,
		  ranap_iu_recv_cb_t iu_recv_cb, ranap_iu_event_cb_t iu_event_cb);

int ranap_iu_tx(struct msgb *msg, uint8_t sapi);

int ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
	OSMO_DEPRECATED("Use ranap_iu_page_cs2 instead");

int ranap_iu_page_ps(const char *imsi, const uint32_t *ptmsi, uint16_t lac, uint8_t rac)
	OSMO_DEPRECATED("Use ranap_iu_page_ps2 instead");

int ranap_iu_page_cs2(const char *imsi, const uint32_t *tmsi, const struct osmo_location_area_id *lai);
int ranap_iu_page_ps2(const char *imsi, const uint32_t *ptmsi, const struct osmo_routing_area_id *rai);

int ranap_iu_rab_act(struct ranap_ue_conn_ctx *ue_ctx, struct msgb *msg);
int ranap_iu_rab_deact(struct ranap_ue_conn_ctx *ue_ctx, uint8_t rab_id);
int ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
			     int send_ck, int new_key);
int ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *ue_ctx, const char *imsi);
int ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause);

/* Transmit a Iu Release Command and submit event RANAP_IU_EVENT_IU_RELEASE upon
 * Release Complete or timeout. Caller is responsible to free the context and
 * closing the SCCP connection (ranap_iu_free_ue) upon recieval of the event. */
void ranap_iu_tx_release_free(struct ranap_ue_conn_ctx *ctx,
			      const struct RANAP_Cause *cause,
			      int timeout);

/* freeing the UE will release all resources
 * This will close the SCCP connection connected to the UE */
void ranap_iu_free_ue(struct ranap_ue_conn_ctx *ue_ctx);
