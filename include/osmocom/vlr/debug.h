#pragma once

#include <osmocom/core/logging.h>
#include <osmocom/sgsn/debug.h>

enum osmo_vlr_cat {
	OSMO_VLR_LOGC_VLR,
	OSMO_VLR_LOGC_SGS,
	_OSMO_VLR_LOGC_MAX,
};

void osmo_vlr_set_log_cat(enum osmo_vlr_cat logc, int logc_num);


// FIXME: private following

extern int g_vlr_log_cat[_OSMO_VLR_LOGC_MAX];

#define LOGVLR(lvl, fmt, args...) LOGP(g_vlr_log_cat[OSMO_VLR_LOGC_VLR], lvl, fmt, ## args)
#define LOGSGS(lvl, fmt, args...) LOGP(g_vlr_log_cat[OSMO_VLR_LOGC_SGS], lvl, fmt, ## args)
