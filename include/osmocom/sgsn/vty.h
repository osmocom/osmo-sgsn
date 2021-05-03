#pragma once

#include <osmocom/vty/command.h>

enum bsc_vty_node {
	SGSN_NODE = _LAST_OSMOVTY_NODE + 1,
	GTPHUB_NODE,
	MME_NODE,
};
