#pragma once

#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/gprs/protocol/gsm_24_301.h>
#include <osmocom/gsm/gsm23003.h>

struct gsn_t;

struct mme_rim_route {
	struct llist_head list; /* item in struct sgsn_mme_ctx */
	struct osmo_eutran_tai tai;
};

struct sgsn_mme_ctx {
	struct llist_head list; /* item in sgsn_mme_ctxts */
	struct llist_head routes; /* list of struct mme_rim_route */
	struct sgsn_instance *sgsn; /* backpointer */
	char *name;
	struct in_addr remote_addr;

	struct osmo_gummei gummei;
	bool gummei_valid;

	/* is it the default route for outgoing message? are all incoming messages accepted? */
	bool default_route;
};
struct sgsn_mme_ctx *sgsn_mme_ctx_alloc(struct sgsn_instance *sgsn, const char *name);
struct sgsn_mme_ctx *sgsn_mme_ctx_find_alloc(struct sgsn_instance *sgsn, const char *name);
void sgsn_mme_ctx_free(struct sgsn_mme_ctx *mme);

struct sgsn_mme_ctx *sgsn_mme_ctx_by_name(const struct sgsn_instance *sgsn, const char *name);
struct sgsn_mme_ctx *sgsn_mme_ctx_by_addr(const struct sgsn_instance *sgsn, const struct in_addr *addr);
struct sgsn_mme_ctx *sgsn_mme_ctx_by_route(const struct sgsn_instance *sgsn, const struct osmo_eutran_tai *tai);
struct sgsn_mme_ctx *sgsn_mme_ctx_by_gummei(const struct sgsn_instance *sgsn, const struct osmo_gummei *gummei);
struct sgsn_mme_ctx *sgsn_mme_ctx_by_default_route(const struct sgsn_instance *sgsn);

void sgsn_mme_ctx_route_add(struct sgsn_mme_ctx *mme, const struct osmo_eutran_tai *tai);
void sgsn_mme_ctx_route_del(struct sgsn_mme_ctx *mme, const struct osmo_eutran_tai *tai);

#define LOGMME(mme, cat, level, fmt, args...) { \
	char _buf[INET_ADDRSTRLEN]; \
	LOGP(cat, level, "MME(%s:%s): " fmt, (mme)->name, inet_ntop(AF_INET, &(mme)->remote_addr, _buf, sizeof(_buf)), ## args); \
	} while (0)
