/* GPRS subscriber details for use in SGSN land */
#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/sgsn/apn.h>

struct sgsn_instance;
struct sgsn_mm_ctx;

extern struct llist_head * const gprs_subscribers;

#define GPRS_SUBSCRIBER_FIRST_CONTACT	0x00000001
#define GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING	(1 << 16)
#define GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING		(1 << 17)
#define GPRS_SUBSCRIBER_CANCELLED			(1 << 18)
#define GPRS_SUBSCRIBER_ENABLE_PURGE			(1 << 19)

#define GPRS_SUBSCRIBER_UPDATE_PENDING_MASK ( \
		GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING | \
		GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING  \
)

struct gsm_auth_tuple {
	int use_count;
	int key_seq;
	struct osmo_auth_vector vec;
};
#define GSM_KEY_SEQ_INVAL	7 /* GSM 04.08 - 10.5.1.2 */

struct sgsn_subscriber_data {
	struct sgsn_mm_ctx	*mm;
	struct gsm_auth_tuple	auth_triplets[5];
	int			auth_triplets_updated;
	struct llist_head	pdp_list;
	int			error_cause;

	uint8_t			msisdn[9];
	size_t			msisdn_len;

	uint8_t			hlr[9];
	size_t			hlr_len;

	uint8_t			pdp_charg[2];
	bool			has_pdp_charg;
};

/* see GSM 09.02, 17.7.1, PDP-Context and GPRSSubscriptionData */
/* see GSM 09.02, B.1, gprsSubscriptionData */
struct sgsn_subscriber_pdp_data {
	struct llist_head	list;

	unsigned int		context_id;
	enum gsm48_pdp_type_org	pdp_type_org;
	enum gsm48_pdp_type_nr	pdp_type_nr;
	struct osmo_sockaddr	pdp_address[2];
	char			apn_str[GSM_APN_LENGTH];
	uint8_t			qos_subscribed[20];
	size_t			qos_subscribed_len;
	uint8_t			pdp_charg[2];
	bool			has_pdp_charg;
};

struct sgsn_subscriber_pdp_data *sgsn_subscriber_pdp_data_alloc(struct sgsn_subscriber_data *sdata);

struct gprs_subscr {
	struct llist_head entry;
	int use_count;

	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	uint32_t tmsi;
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];
	bool authorized;
	bool keep_in_ram;
	uint32_t flags;
	uint16_t lac;

	struct sgsn_subscriber_data *sgsn_data;
};

struct gprs_subscr *_gprs_subscr_get(struct gprs_subscr *gsub,
				     const char *file, int line);
struct gprs_subscr *_gprs_subscr_put(struct gprs_subscr *gsub,
				     const char *file, int line);
#define gprs_subscr_get(gsub) _gprs_subscr_get(gsub, __FILE__, __LINE__)
#define gprs_subscr_put(gsub) _gprs_subscr_put(gsub, __FILE__, __LINE__)

int gprs_subscr_init(struct sgsn_instance *sgi);
int gprs_subscr_request_update_location(struct sgsn_mm_ctx *mmctx);
int gprs_subscr_request_auth_info(struct sgsn_mm_ctx *mmctx,
				  const uint8_t *auts,
				  const uint8_t *auts_rand);
void gprs_subscr_cleanup(struct gprs_subscr *subscr);
struct gprs_subscr *gprs_subscr_get_or_create(const char *imsi);
struct gprs_subscr *gprs_subscr_get_or_create_by_mmctx(struct sgsn_mm_ctx *mmctx);
struct gprs_subscr *gprs_subscr_get_by_imsi(const char *imsi);
void gprs_subscr_cancel(struct gprs_subscr *subscr);
void gprs_subscr_update(struct gprs_subscr *subscr);
void gprs_subscr_update_auth_info(struct gprs_subscr *subscr);
int gprs_subscr_rx_gsup_message(struct msgb *msg);

#define LOGGSUBSCRP(level, subscr, fmt, args...) \
	LOGP(DGPRS, level, "SUBSCR(%s) " fmt, \
	     (subscr) ? (subscr)->imsi : "---", \
	     ## args)
