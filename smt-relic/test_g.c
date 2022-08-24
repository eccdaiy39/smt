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

#include "relic.h"
#include "relic_bench.h"

int test_g2_is_valid_bn(g2_t a) {


	if (g2_is_infty(a)) {
		return 0;
	}

	bn_t  n;
	g2_t u0, u1, u2, u3;
	int r = 0;

	bn_null(n);
	g2_null(u0);
	g2_null(u1);
	g2_null(u2);
	g2_null(u3);
	RLC_TRY {
		bn_new(n);
		g2_new(u0);
		g2_new(u1);
		g2_new(u2);
		g2_new(u3);

       		 fp_prime_get_par(n);

		/* Compute v = a^(n+1)*a^(np)*a^(np^2) and a^(np^3). */
			g2_copy(u1, a);
			for (int i = bn_bits(n) - 2; i >= 0; i--) {
				g2_dbl(u1, u1);
				if (bn_get_bit(n, i)) {
					g2_add(u1, u1, a);
				}
			}
		if (bn_sign(n) == RLC_NEG) {
				g2_neg(u1, u1);
			}
		g2_add(u0, u1, a);
		g2_dbl(u3, u1);
		g2_frb(u2, u1, 2);
		g2_frb(u1, u1, 1);
		g2_frb(u3, u3, 3);
		g2_add(u0, u0, u1);
		g2_add(u0, u0, u2);
		/* Check that u0 = u3. */
		//r = g2_on_curve(a) && (g2_cmp(u0, u3) == RLC_EQ);
		r = g2_on_curve(a);
		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u0);
		g2_free(u1);
		g2_free(u2);
		g2_free(u3);
	}
	return r;
}
int test_g2_is_valid(g2_t a) {
#if FP_PRIME >= 1536
	if (pc_map_is_type1()) {
		return g1_is_valid(a);
	}
#else

	if (g2_is_infty(a)) {
		return 0;
	}

	bn_t p, n;
	g2_t u, v;
	int r = 0;

	bn_null(n);
	bn_null(p);
	g2_null(u);
	g2_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(p);
		g2_new(u);
		g2_new(v);
	//bench_before();															\
        fp_prime_get_par(n);
		pc_get_ord(n);
		ep_curve_get_cof(p);

		if (bn_cmp_dig(p, 1) == RLC_EQ) {
			/* Trick for curves of prime order or subgroup-secure. */
			bn_mul(n, n, p);
			dv_copy(p->dp, fp_prime_get(), RLC_FP_DIGS);
			p->used = RLC_FP_DIGS;
			p->sign = RLC_POS;
			/* Compute trace t = p - n + 1. */
			bn_sub(n, p, n);
			bn_add_dig(n, n, 1);
			g2_mul(u, a, n);
			if (bn_sign(n) == RLC_NEG) {
				g2_neg(u, u);
			}
//bench_after();	
	//bench_compute(BENCH * BENCH);											\
	bench_print();
			/* Compute v = a^(p + 1). */
			g2_frb(v, a, 1);
			g2_add(v, v, a);
			/* Check if a^(p + 1) = a^t. */
			r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
		} else {
			switch (ep_curve_is_pairf()) {
				/* Formulas from "Faster Subgroup Checks for BLS12-381" by Bowe.
				 * https://eprint.iacr.org/2019/814.pdf */
				case EP_B12:
#if FP_PRIME == 383
					/* Since p mod n = r, we can check instead that
					 * psi^4(P) + P == \psi^2(P). */
					ep2_frb(u, a, 4);
					ep2_add(u, u, a);
					ep2_frb(v, a, 2);
#else
					/* Check [z]psi^3(P) + P == \psi^2(P). */
					fp_prime_get_par(n);
					g2_copy(u, a);
					for (int i = bn_bits(n) - 2; i >= 0; i--) {
						g2_dbl(u, u);
						if (bn_get_bit(n, i)) {
							g2_add(u, u, a);
						}
					}
					if (bn_sign(n) == RLC_NEG) {
						g2_neg(u, u);
					}
					g2_frb(u, u, 3);
					g2_frb(v, a, 2);
					g2_add(u, u, a);
#endif
					r = g2_on_curve(a) && (g2_cmp(u, v) == RLC_EQ);
					break;
				default:
					pc_get_ord(n);
					bn_sub_dig(n, n, 1);
					/* Otherwise, check order explicitly. */
					/* We use fast scalar multiplication methods here, because
					 * they should work only in the correct order. */
					g2_mul(u, a, n);
					g2_neg(u, u);
					r = g2_on_curve(a) && (g2_cmp(u, a) == RLC_EQ);
					break;
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(p);
		bn_free(n);
		g2_free(u);
		g2_free(v);
	}

	return r;
#endif
}

int main(void) {
core_init(); 
	fp_prime_init();
	ep_param_set_any_pairf();
        fp_param_print();
	ep2_t g2;
	ep2_null(g2);
	ep2_rand(g2);									\
	printf("%d\n",test_g2_is_valid_bn(g2));
	BENCH_RUN("g2_is_valid") {
		BENCH_ADD(g2_is_valid(g2));
	}
	BENCH_END;

	BENCH_RUN("g2_is_valid_bn") {
		BENCH_ADD(g2_is_valid_bn(g2));
	}
	BENCH_END;



	return 0;
}
