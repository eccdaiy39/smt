/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Benchmarks for elliptic curves defined over extensions of prime fields.
 *
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"
#include "relic_epx.h"



static void hash(void) {
	ep13_t p, q;

	ep13_null(p);
	ep13_null(q);
	ep13_new(p);
	ep13_new(q);
	BENCH_RUN("multiplcation by the seeu u on BW3-P310") {
		BENCH_ADD(ep13_rand_mul_u(q, p));
	}
	BENCH_END;
	BENCH_RUN("hashing to ellptic curves on BW13-P310") {
		uint8_t msg[5];
		rand_bytes(msg, 5);
		BENCH_ADD(ep13_map(p, msg, 5));
	} BENCH_END;
	BENCH_RUN("mapping a point to G2 on BW3-P310 using our method") {
		ep13_rand(p);
		BENCH_ADD(ep13_cof(q, p));
	}
	BENCH_END;

	BENCH_RUN("mapping a point to G2 on BW3-P310 using the generalized fuentes et al's method") {
		ep13_rand(p);
		BENCH_ADD(ep13_cof_fuentes(q, p));
	}
	BENCH_END;

	

}



int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for hashing to G2:", 0);

	if (ep_param_set_any_pairf() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}
	hash();
	core_clean();
	return 0;
}
