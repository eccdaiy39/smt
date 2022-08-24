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
#include "relic/relic.h"
#include "relic/relic_pc.h"
int test_g1_is_valid_bw13(ep_t a) {


	if (ep_is_infty(a)) {
		return 0;
	}

	bn_t  n;
	ep_t u0, u1, u2;
	int r = RLC_NE;

	bn_null(n);
	ep_null(u0);
	ep_null(u1);
	ep_null(u2);
	ep_null(u3);
	RLC_TRY {
		fp_prime_get_par(n);

		ep_mul_basic(u0, a, n);
		
		ep_mul_basic(u1, u0, n);
		ep_mul_basic(u1, u1, n);
		ep_mul_basic(u2, u1, n);
		ep_add(u0, u0, a);
		ep_add(u1, u1, u2);
		ep_sub(u0, u1, u0);
		ep_mul_basic(u0, u0, n);
		ep_mul_basic(u1, u0, n);
                for(int i = 0; i < 5; i++)ep_mul_basic(u1, u1, n);
		ep_add(u0, u0, u1);
		ep_neg(u0, u0);

		ep_mul_basic(u1, u0, n);
		ep_sub(u1, a, u1);
           	ep_psi(u1, u1);
		r = (ep_on_curve(a)) && (ep_cmp(u0,u1) == RLC_EQ);



		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		ep_free(u0);
		ep_free(u1);
		ep_free(u2);

	}
	return r;
}
int test_g2_is_valid_bw13(ep13_t a) {


	if (ep13_is_infty(a)) {
		return 0;
	}

	bn_t  n;
	ep13_t u0, u1, v0, v1, v2, v3;
	int r = RLC_NE;

	bn_null(n);
	g2_null(u0);
	g2_null(u1);
	g2_null(u2);
	g2_null(u3);
	RLC_TRY {
		ep13_rand_mul_u(u0, a);
		ep13_neg(u0, u0);


                ep13_psi(u1, a, 1);


 		ep13_frb(v0, a, 1);
 		ep13_frb(v1, a, 2);
                ep13_add(v0, v0, v1);
		ep13_frb(v1, v0, 2);
		ep13_add(v1, v0, v1);
		ep13_frb(v2, v1, 4);
		ep13_frb(v3, v2, 4);		
		ep13_add(v0, v1, v2);
		ep13_add(v0, v0, v3);
		ep13_neg(v1, a);
           
		r = ep13_on_curve(a) && (ep13_cmp(u0, u1) == RLC_EQ) && (ep13_cmp(v0, v1) == RLC_EQ);

		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		ep13_free(u0);
		ep13_free(u1);
		ep13_free(v0);
		ep13_free(v1);
		ep13_free(v2);
		ep13_free(v3);
	}
	return r;
}

int test_gt_is_valid_bw13(fp13_t a) {


	if (fp13_is_zero(a)||(fp13_cmp_dig(a,1) == RLC_EQ)) {
		return 0;
	}

	bn_t  n;
	fp13_t u0, u1, u2, u3;
	int r = RLC_NE;

	bn_null(n);
	fp13_null(u0);
	fp13_null(u1);
	fp13_null(u2);
	fp13_null(u3);
	RLC_TRY {
		fp_prime_get_par(n);
		bn_neg(n,n);
		/*checking a is a element of cyclotomic subgroup of F^13_{p}*/
		fp13_frb(u1, a, 1);
		fp13_frb(u2, a, 2);
		fp13_mul(u1, u1, u2);
		fp13_frb(u2, u1, 2);
		fp13_mul(u1, u1, u2);

		fp13_frb(u2, u1, 4);
		fp13_frb(u0, u2, 4);	
		fp13_mul(u1, u0, u1);	
		fp13_mul(u1, u1, u2);
		fp13_mul(u1, u1, a);
	        /*the vector C is selected as [n^2, -n, 1]*/
           	fp13_exp(u0, a, n);
		fp13_exp(u3, u0, n);
		fp13_frb(u0, u0, 1);
		fp13_frb(u2, a, 2);
		fp13_mul(u0, u0, u3);
		fp13_mul(u0, u0, u2);
	
		r =  (fp13_cmp_dig(u0,1) == RLC_EQ) && (fp13_cmp_dig(u1,1) == RLC_EQ);

		} 	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		fp13_free(u0);
		fp13_free(u1);
		fp13_free(u2);
		fp13_free(u3);

	}
	return r;
}

int main(void) {
	core_init();
	ep_param_set_any_pairf();
	ep_t p;
	ep13_t a;
	fp13_t h0, h1;

	ep_curve_get_gen(p);
	ep13_rand(a);

	fp13_rand(h0);
	fp13_rand(h1);
	pp_exp_bwk13(h0, h0, h1); 



	printf("%d\n", g1_is_valid_bw13(p));
	printf("%d\n", g2_is_valid_bw13(a));
	printf("%d\n", gt_is_valid_bw13(h0));
	printf("%d\n", gt_is_valid_bw13(h1));
	return 0;
}
