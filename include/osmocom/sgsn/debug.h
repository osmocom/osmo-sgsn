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
	DNS,
	DLLC,
	DSNDCP,
	DSLHC,
	DCTRL,
	DFILTER,
	DGTPHUB,
	DRANAP,
	DSUA,
	DV42BIS,
	DIUCS,
	DSIGTRAN,
	DGTP,
	DOBJ,
	Debug_LastEntry,
};

extern const struct log_info log_info;
