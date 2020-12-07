#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

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
	DHO,
	DDB,
	DREF,
	DGPRS,
	DNS,
	DLLC,
	DSNDCP,
	DSLHC,
	DNAT,
	DCTRL,
	DFILTER,
	DGTPHUB,
	DRANAP,
	DSUA,
	DV42BIS,
	DPCU,
	DVLR,
	DIUCS,
	DSIGTRAN,
	DGTP,
	DOBJ,
	Debug_LastEntry,
};

extern const struct log_info log_info;
