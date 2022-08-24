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
 * Implementation of point multiplication on prime elliptic curves over
 * quadratic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

#if defined(EP_ENDOM)

static void ep13_mul_glv_imp(ep13_t r, ep13_t p, const bn_t k) {
	int sign, i, j, l, _l[24];
	bn_t n, _k[24], u, v;
	int8_t naf[24][RLC_FP_BITS + 1];
	ep13_t q[24];

	bn_null(n);
	bn_null(u);
	bn_null(v);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		bn_new(v);
		for (i = 0; i < 24; i++) {
			bn_null(_k[i]);
			ep13_null(q[i]);
			bn_new(_k[i]);
			ep13_new(q[i]);
		}

        bn_abs(v, k);
		ep_curve_get_ord(n);
        if (bn_cmp_abs(v, n) == RLC_GT) {
            bn_mod(v, v, n);
        }

		fp_prime_get_par(u);
		sign = bn_sign(u);
        bn_abs(u, u);

		ep13_norm(q[0], p);
		for (i = 0; i < 24; i++) {
			bn_mod(_k[i], v, u);
			bn_div(v, v, u);
			if ((sign == RLC_NEG) && (i % 2 != 0)) {
				bn_neg(_k[i], _k[i]);
			}
            if (bn_sign(k) == RLC_NEG) {
                bn_neg(_k[i], _k[i]);
            }
            if (i > 0) {
                ep13_frb(q[i], q[i - 1], 1);
            }
		}

        l = 0;
		for (i = 0; i < 24; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep13_neg(q[i], q[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _k[i], 2);
            l = RLC_MAX(l, _l[i]);
		}

		ep13_set_infty(r);
		for (j = l - 1; j >= 0; j--) {
			ep13_dbl(r, r);

			for (i = 0; i < 24; i++) {
				if (naf[i][j] > 0) {
					ep13_add(r, r, q[i]);
				}
				if (naf[i][j] < 0) {
					ep13_sub(r, r, q[i]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep13_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
        bn_free(u);
        bn_free(v);
		for (i = 0; i < 24; i++) {
			bn_free(_k[i]);
			ep13_free(q[i]);
		}

	}
}

#endif /* EP_ENDOM */

static void ep13_mul_naf_imp(ep13_t r, ep13_t p, const bn_t k) {
	int l, i, n;
	int8_t naf[RLC_FP_BITS + 1];
	ep13_t t[1 << (EP_WIDTH - 2)];

	RLC_TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep13_null(t[i]);
			ep13_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep13_tab(t, p, EP_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, k, EP_WIDTH);

		ep13_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep13_dbl(r, r);

			n = naf[i];
			if (n > 0) {
				ep13_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ep13_sub(r, r, t[-n / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep13_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep13_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep13_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep13_mul_basic(ep13_t r, ep13_t p, const bn_t k) {
	int i, l;
	ep13_t t;

	ep13_null(t);

	if (bn_is_zero(k) || ep13_is_infty(p)) {
		ep13_set_infty(r);
		return;
	}

	RLC_TRY {
		ep13_new(t);
		l = bn_bits(k);

		if (bn_get_bit(k, l - 1)) {
			ep13_copy(t, p);
		} else {
			ep13_set_infty(t);
		}

		for (i = l - 2; i >= 0; i--) {
			ep13_dbl(t, t);
			if (bn_get_bit(k, i)) {
				ep13_add(t, t, p);
			}
		}

		ep13_copy(r, t);
		ep13_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep13_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep13_free(t);
	}
}

#if EP_MUL == SLIDE || !defined(STRIP)

void ep13_mul_slide(ep13_t r, ep13_t p, const bn_t k) {
	ep13_t t[1 << (EP_WIDTH - 1)], q;
	int i, j, l;
	uint8_t win[RLC_FP_BITS + 1];

	ep13_null(q);

	if (bn_is_zero(k) || ep13_is_infty(p)) {
		ep13_set_infty(r);
		return;
	}

	RLC_TRY {
		for (i = 0; i < (1 << (EP_WIDTH - 1)); i ++) {
			ep13_null(t[i]);
			ep13_new(t[i]);
		}

		ep13_new(q);

		ep13_copy(t[0], p);
		ep13_dbl(q, p);

#if defined(EP_MIXED)
		ep13_norm(q, q);
#endif

		/* Create table. */
		for (i = 1; i < (1 << (EP_WIDTH - 1)); i++) {
			ep13_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep13_norm_sim(t + 1, t + 1, (1 << (EP_WIDTH - 1)) - 1);
#endif

		ep13_set_infty(q);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, k, EP_WIDTH);
		for (i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep13_dbl(q, q);
			} else {
				for (j = 0; j < util_bits_dig(win[i]); j++) {
					ep13_dbl(q, q);
				}
				ep13_add(q, q, t[win[i] >> 1]);
			}
		}

		ep13_norm(r, q);
		if (bn_sign(k) == RLC_NEG) {
			ep13_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < (1 << (EP_WIDTH - 1)); i++) {
			ep13_free(t[i]);
		}
		ep13_free(q);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep13_mul_lwnaf(ep13_t r, ep13_t p, const bn_t k) {
	if (bn_is_zero(k) || ep13_is_infty(p)) {
		ep13_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		if (ep_curve_opt_a() == RLC_ZERO) {
			ep13_mul_glv_imp(r, p, k);
		} else {
			ep13_mul_naf_imp(r, p, k);
		}
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep13_mul_naf_imp(r, p, k);
#endif
}

#endif
void  ep13_rand_mul_u(ep13_t r, ep13_t q) {
		RLC_TRY {
		 ep13_dbl(r,q);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_add(r,r,q);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_add(r,r,q);
 		 ep13_dbl(r,r);
		 ep13_add(r,r,q);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_dbl(r,r);
		 ep13_neg(r, r);
		
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
	}
}

void  ep13_cof(ep13_t r, ep13_t p) {
	  ep13_t R[15]; 
	  ep13_t u0, u1, u2, q;
	  for(int i=0; i<15;i++)ep13_null(R[i]);
	  ep13_null(u0);
	  ep13_null(u1);
	  ep13_null(u2);
	  ep13_null(q);

		RLC_TRY {
		fp13_frb(q->x, p->x, 1);
		fp13_frb(q->y, p->y, 1);
		fp13_zero(q->z);
		fp_set_dig(q->z[0], 1);
		ep13_sub(q, q, p);

		ep13_dbl(R[14], q);
		ep13_rand_mul_u(u0, q);//uQ
		ep13_sub(u1, u0, q);//(u-1)Q
		ep13_rand_mul_u(u2, u0);//u^2Q
		ep13_sub(R[12], u2, u1);//(u^2-u+1)Q
		
		for(int i=1; i<12; i++){
			ep13_rand_mul_u(R[12-i], R[13-i]);
			ep13_neg(R[12-i], R[12-i]);
		}
		ep13_add(R[1], R[1], q);
		ep13_neg(R[0], u0);
		for(int i=1; i<5;i++){
			ep13_add(R[0], R[0], R[3*i-2]);
			ep13_add(u1, u1, R[3*i-1]);
		}

		ep13_add(u2, R[3], R[6]);
		ep13_add(u2, u2, R[9]);
		ep13_add(u2, u2, R[12]);
		ep13_sub(R[13], R[0], u1);
		ep13_sub(R[0], R[0], u2);
		
		for(int i=1; i<15;i++){
			ep13_psi(R[i], R[i], i);
			ep13_add(R[0], R[0], R[i]);
		}
		ep13_copy(r, R[0]);
		ep13_norm(r, r);
} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		 for(int i=0; i<15;i++)ep13_free(R[i]);
	 	 ep13_free(u0);
	 	 ep13_free(u1);
	 	 ep13_free(u2);
	     ep13_free(q);
	}
}

void  ep13_cof_fuentes(ep13_t r, ep13_t p) {
	  ep13_t R[15]; 
	  ep13_t L[13]; 
	  ep13_t u0;

	  for(int i=0; i<15; i++)ep13_null(R[i]);
	  for(int i=0; i<13; i++)ep13_null(L[i]);
	  ep13_null(u0);

		RLC_TRY {
			for(int i=0; i<15; i++)ep13_new(R[i]);
	  		for(int i=0; i<13; i++)ep13_new(L[i]);
	 		ep13_null(u0);
			 /*mapping p into the cyclotomic zero subgroup,i.e., corrsponding to the mapping \tau*/
			ep13_frb(R[0], p, 1);
			ep13_sub(R[0], R[0], p);

			for(int i=1; i<15; i++)ep13_rand_mul_u(R[i], R[i-1]);
		
		/*L[i] corresponds to L_{i} in the paper*/
			ep13_sub(L[0], R[14], R[13]);
			ep13_add(L[0], L[0], R[12]);
			for(int i=1; i<13; i++)ep13_rand_mul_u(L[i], L[i-1]);

		/*R[3*i+1] and R[3i+2] correspond to R_{i} and H_{i} in the paper*/
			for(int i=0; i< 4; i++){
				ep13_dbl(R[3*i+2], R[3*i+2]);
				ep13_add(R[3*i+2], R[3*i+2], R[3*i+1]);
				ep13_sub(R[3*i+1], R[3*i+2], R[3*i]);
				ep13_dbl(u0, R[3*i+3]);		
				ep13_sub(R[3*i+2], u0, R[3*i+2]);
			}
			

		/* compute \pi^(i)(l_iP), where P=R[0] */

		/*L[3*i+2]=(-1)^il_{6-3*i}P_{6-3*i} for i=0,1,2
		L[3*i]=(-1)^(i+1)l_{8-3*i}P_{8-3*i} for i=0,1,2
		L[12]=l_9P_9, L[11]=-l_{10}P_{10}, L_{9}=l_{12}P_9,
		where P_i=\pi^i(P)
		*/
			for(int i=0; i < 3; i++){
				ep13_add(L[8-3*i],L[8-3*i], R[8-3*i]);
				ep13_frb(L[8-3*i], L[8-3*i], 3*i);
				ep13_dbl(u0, R[6-3*i]);
				ep13_add(u0, u0,  R[6-3*i]);
				ep13_sub(L[6-3*i], L[6-3*i], u0);
				ep13_frb(L[6-3*i], L[6-3*i], 3*i+2);	
			}      
			ep13_sub(R[12], R[12], R[0]);
			ep13_dbl(u0, R[12]);
			ep13_add(R[12], R[12], u0);
			ep13_sub(L[12], R[12], L[12]);
			ep13_frb(L[12], L[12], 9);

			ep13_add(L[11], L[11], R[11]);
			ep13_frb(L[11], L[11], 10);
		

			ep13_dbl(u0, R[9]);
			ep13_add(u0, u0, R[9]);
			ep13_sub(L[9], L[9], u0);
			ep13_frb(L[9], L[9], 12);
	
		
       /* R[1]=l_7P_7, R[4]=-l_4P_4, R[7]=l_1P_1, R[10]=-l_{11}P_{11}*/
       		ep13_frb(R[1], R[1], 7);
			ep13_frb(R[4], R[4], 4);
			ep13_frb(R[7], R[7], 1);
			ep13_frb(R[10], R[10], 11);


		/*the final step*/
			ep13_sub(R[1], R[1], R[4]);
			ep13_add(R[1], R[1], R[7]);
			ep13_sub(R[1], R[1], R[10]);
			ep13_add(R[1], R[1], L[8]);
			ep13_sub(R[1], R[1], L[5]);
			ep13_add(R[1], R[1], L[2]);
			ep13_sub(R[1], R[1], L[6]);
			ep13_add(R[1], R[1], L[3]);
			ep13_sub(R[1], R[1], L[0]);
			ep13_add(R[1], R[1], L[12]);
			ep13_sub(R[1], R[1], L[11]);	
			ep13_add(R[1], R[1], L[9]);
			ep13_norm(r, R[1]);
	  } RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
			for(int i=0; i<15; i++)ep13_free(R[i]);
	  		for(int i=0; i<13; i++)ep13_free(L[i]);
	 		ep13_free(u0);
	}
}

