#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/gprs/protocol/gsm_24_301.h>

struct gsn_t;
struct sgsn_pdp_ctx;
struct sgsn_instance;

struct sgsn_ggsn_ctx {
	struct llist_head list;
	uint32_t id;
	unsigned int gtp_version;
	struct in_addr remote_addr;
	int remote_restart_ctr;
	struct gsn_t *gsn;
	struct llist_head pdp_list;	/* list of associated pdp ctx (struct sgsn_pdp_ctx*) */
	struct osmo_timer_list echo_timer;
	unsigned int echo_interval;
};
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_alloc(struct sgsn_instance *sgsn, uint32_t id);
void sgsn_ggsn_ctx_free(struct sgsn_ggsn_ctx *ggc);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_id(struct sgsn_instance *sgsn, uint32_t id);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_addr(struct sgsn_instance *sgsn, struct in_addr *addr);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_find_alloc(struct sgsn_instance *sgsn, uint32_t id);
void sgsn_ggsn_ctx_drop_pdp(struct sgsn_pdp_ctx *pctx);
int sgsn_ggsn_ctx_drop_all_pdp_except(struct sgsn_ggsn_ctx *ggsn, struct sgsn_pdp_ctx *except);
int sgsn_ggsn_ctx_drop_all_pdp(struct sgsn_ggsn_ctx *ggsn);
void sgsn_ggsn_ctx_add_pdp(struct sgsn_ggsn_ctx *ggc, struct sgsn_pdp_ctx *pdp);
void sgsn_ggsn_ctx_remove_pdp(struct sgsn_ggsn_ctx *ggc, struct sgsn_pdp_ctx *pdp);
void sgsn_ggsn_ctx_check_echo_timer(struct sgsn_ggsn_ctx *ggc);

#define LOGGGSN(ggc, level, fmt, args...) { \
	char _buf[INET_ADDRSTRLEN]; \
	LOGP(DGTP, level, "GGSN(%" PRIu32 ":%s): " fmt, (ggc)->id, inet_ntop(AF_INET, &(ggc)->remote_addr, _buf, sizeof(_buf)), ## args); \
	} while (0)
