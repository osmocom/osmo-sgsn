#pragma once

#include <stdio.h>
#include <osmocom/core/linuxlist.h>

#define DEBUG
#include <osmocom/core/logging.h>

/* Debug Areas of the code */
enum {
	DMM,
	DPAG,
	DMEAS,
	DREF,
	DGPRS,
	DLLC,
	DSNDCP,
	DSLHC,
	DCTRL,
	DFILTER,
	DGTPHUB,
	DRANAP,
	DSUA,
	DV42BIS,
	DSIGTRAN,
	DGTP,
	DOBJ,
	DRIM,
	DRA, /* Routing Area handling */
	DVLR,
	DSGS, /* SGS is only used by the MSC, but libvlr shared libvlr code is using DSGS. To be removed. */
	Debug_LastEntry,
};

extern const struct log_info log_info;
