#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

struct gprs_subscr;

/* Debug Areas of the code */
enum {
	DRLL,
	DCC,
	DMM,
	DRR,
	DRSL,
	DNM,
	DMNCC,
	DPAG,
	DMEAS,
	DSCCP,
	DMSC,
	DMGCP,
	DHO,
	DDB,
	DREF,
	DGPRS,
	DNS,
	DBSSGP,
	DLLC,
	DSNDCP,
	DSLHC,
	DNAT,
	DCTRL,
	DSMPP,
	DFILTER,
	DGTPHUB,
	DRANAP,
	DSUA,
	DV42BIS,
	DPCU,
	DVLR,
	DIUCS,
	DSIGTRAN,
	Debug_LastEntry,
};

enum sgsn_log_flt {
	LOG_FLT_GPRS_SUBSCR = _LOG_FLT_COUNT,
	_LOG_FLT_COUNT_SGSN
};

enum sgsn_log_ctx_index {
	LOG_CTX_GPRS_SUBSCR = _LOG_CTX_COUNT,
	_LOG_CTX_COUNT_SGSN
};

extern const struct log_info log_info;

void log_set_filter_gprs_subscriber(struct log_target *target,
				    struct gprs_subscr *gsub);
