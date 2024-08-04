/*! \file gprs_routing_area.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>

struct osmo_routing_area_id;
struct osmo_cell_global_id_ps;

void sgsn_rau_init();

int sgsn_rau_bvc_reset_ind(uint16_t nsei, uint16_t bvci, struct osmo_cell_global_id_ps *cgi_ps);

bool sgsn_rau_valid_rau(struct osmo_routing_area_id *ra_id);

