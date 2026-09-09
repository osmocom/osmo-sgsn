/* MS authorization and subscriber data handling */
#pragma once

#include <osmocom/core/linuxlist.h>

struct sgsn_config;
struct sgsn_instance;
struct sgsn_mm_ctx;
struct gsm_auth_tuple;

/* Authorization/ACL handling */
enum sgsn_auth_state {
	SGSN_AUTH_UNKNOWN,
	SGSN_AUTH_AUTHENTICATE,
	SGSN_AUTH_UMTS_RESYNC,
	SGSN_AUTH_ACCEPTED,
	SGSN_AUTH_REJECTED
};

extern const struct value_string *sgsn_auth_state_names;

/* Request authorization */
enum sgsn_auth_state sgsn_auth_state(struct sgsn_mm_ctx *mm);
int sgsn_auth_request(struct sgsn_mm_ctx *mm);
void sgsn_auth_update(struct sgsn_mm_ctx *mm);
struct gsm_auth_tuple *sgsn_auth_get_tuple(struct sgsn_mm_ctx *mmctx,
					   unsigned key_seq);
