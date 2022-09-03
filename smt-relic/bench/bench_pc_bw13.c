/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Benchmarks for Pairing-Based Cryptography.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_pc.h"
#include "relic_pp.h"
#include "relic_bench.h"



static void G1(void) {
	ep_t p;
	ep_null(p);
	ep_new(p);
	BENCH_RUN("g1_is_valid") {
		ep_rand(p);
		BENCH_ADD(g1_is_valid_bw13(p));
	} BENCH_END;
	ep_free(p);

}
static void G2(void) {
	ep13_t q;
	ep13_null(q);
	ep13_new(q);
	BENCH_RUN("g2_is_valid") {
		ep13_rand(q);
		BENCH_ADD(g2_is_valid_bw13(q));
	} BENCH_END;
	ep13_free(q);

}

static void Gt(void) {
	fp13_t h0, h1;
	fp13_null(h0);
	fp13_null(h1);
	fp13_new(h0);
	fp13_new(h1);
	fp13_rand(h0);
	fp13_rand(h1);
	pp_exp_bwk13(h0, h0, h1); 
	BENCH_RUN("gt_is_valid") {
		BENCH_ADD(gt_is_valid_bw13(h0));
	} BENCH_END;

}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();



	if (ep_param_set_any_pairf() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	util_banner("G1:", 0);
	G1();
	util_banner("G2:", 0);
	G2();
	util_banner("Gt:", 0);
	Gt();
	core_clean();
	return 0;
}
