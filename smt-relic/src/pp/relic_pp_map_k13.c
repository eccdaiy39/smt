/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the pairings over prime curves.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Compute the modified Miller loop  for super-optimal ate pairings of type G_2 x G_1 with k=13.
 *
 * @param[out] t			- the resulting point.
 * @param[in] q				- the vector of first arguments in affine coordinates.
 * @param[in] p				- the vector of second arguments in affine coordinates.
 * @param[in] p2			- the image of p under the glv endomorphism.
 * @param[in] a				- the loop parameter.
 * @param[out] l1			- numerator of f_{a,q}(p).
 * @param[out] l2			- denominator of f_{a,q}(p).
 * @param[out] s1			- numerator of f_{a,q}(p2).
 * @param[out] s2			- denominator of f_{a,q}(p2).
 */
static void pp_mil_k13(fp13_t l1, fp13_t l2, fp13_t s1, fp13_t s2, ep13_t t, ep13_t q, ep_t p, ep_t p2, bn_t a) {
	fp13_t f1, g1, f2, g2;
	fp13_null(f1);
	fp13_null(g1);
	fp13_null(f2);
	fp13_null(g2);
	RLC_TRY {
		fp13_new(f1);
		fp13_new(g1);
		fp13_new(f2);
		fp13_new(g2);
		ep13_copy(t, q);
		pp_qpl_k13_projc_lazyr(l1, l2, s1, s2, t, p, p2);
		fp13_neg(f1, q->x);
		fp13_neg(f2, q->x);
		fp_add(f1[0], f1[0], p->x);
		fp_add(f2[0], f2[0], p2->x);
		fp13_sqr(f1, f1);
		fp13_sqr(f1, f1);
		fp13_mul(l1, l1, f1);
		fp13_sqr(l2, l2);

		fp13_sqr(f2, f2);
		fp13_sqr(f2, f2);
		fp13_mul(s1, s1, f2);
		fp13_sqr(s2, s2);
		for (int i = bn_bits(a) - 4; i >= 0;) {
			if (bn_get_bit(a, i)) {
				pp_dba_k13_projc_lazyr(f1, g1, f2, g2, t, q, p, p2);
				fp13_sqr(l1, l1);
				fp13_sqr(l2, l2);
				fp13_mul(l1, l1, f1);
				fp13_mul(l2, l2, g1);

				fp13_sqr(s1, s1);
				fp13_sqr(s2, s2);
				fp13_mul(s1, s1, f2);
				fp13_mul(s2, s2, g2);
				i--;
			}
			else{
				pp_qpl_k13_projc_lazyr(f1, g1, f2, g2, t, p, p2);
				fp13_sqr(l1, l1);
				fp13_sqr(l1, l1);
				fp13_mul(l1, l1, f1);


				fp13_sqr(l2, l2);
				fp13_mul(l2, l2, g1);
				fp13_sqr(l2, l2);

				fp13_sqr(s1, s1);
				fp13_sqr(s1, s1);
				fp13_mul(s1, s1, f2);


				fp13_sqr(s2, s2);
				fp13_mul(s2, s2, g2);
				fp13_sqr(s2, s2);

				i--;
				if (bn_get_bit(a, i)) {
					pp_add_k13_projc_lazyr(f1, g1, f2, g2, t, q, p, p2);
					fp13_mul(l1, l1, f1);
					fp13_mul(l2, l2, g1);	

					fp13_mul(s1, s1, f2);
					fp13_mul(s2, s2, g2);
				}
				i--;
		
						
			}
			
		}
	fp13_sqr(g1, t->z);
	fp13_mul(l1, l1, g1);
	fp13_mul(s1, s1, g1);
	for(int i = 0; i<13; i++)fp_mul(f1[i], g1[i], p->x);	
	for(int i = 0; i<13; i++)fp_mul(f2[i], g1[i], p2->x);

	fp13_sub(f1, f1, t->x);
	fp13_mul(l2, l2, f1);
	fp13_sub(f2, f2, t->x);
	fp13_mul(s2, s2, f2);
	}
	
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(f1);
		fp13_free(g1);
		fp13_free(f2);
		fp13_free(g2);
		
	}


}
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_map_sup_oatep_k13(fp13_t r, ep_t p, ep13_t q) {
	bn_t a;
	ep_t p2;
	ep13_t t;
	fp13_t l1,l2, s1, s2, h1;

	bn_null(a);
	ep_null(p2);
	ep13_null(t);
        fp13_null(l1);
        fp13_null(l2);
	fp13_null(s1);
	fp13_null(s2);

	RLC_TRY {

		bn_new(a);
       		fp13_new(l1);
        	fp13_new(l2);
        	fp13_new(s1);
       		fp13_new(s2);
		ep_new(p2);
		ep13_new(t);
		fp_prime_get_par(a);
		fp13_set_dig(r, 1);
		dig_t* w;
		w = ep_curve_get_beta();
       		ep_copy(p2, p);
		ep13_copy(t, q);
		fp_mul(p2->x, p->x, w);

		if (!ep_is_infty(p) && !ep13_is_infty(q)) {
					/* r = f_{|a|,Q}(P). */
			bn_neg(a, a);
			pp_mil_k13(l1, l2, s1, s2,  t, q, p, p2, a);
			/*compute (l1/l2)^(a+p)*(s1/s2)^p*/
			fp13_frb(s1, s1, 1);
			fp13_frb(s2, s2, 1);
			fp13_inv(l2, l2);
			fp13_mul(l1, l1, l2);
			fp13_frb(l2, l1, 1);
			fp13_copy(h1, l1);
			for (int i = bn_bits(a) - 2; i >= 0;){
				fp13_sqr(h1, h1);
				if (bn_get_bit(a, i))fp13_mul(h1, h1, l1);
				i--;
		         }

			fp13_mul(l1, h1, l2);
			fp13_mul(l1, l1, s1);
			/*compute the final line function l_{p^2(Q),p(aQ)(P)}*/
                        fp13_frb(h1, q->y,2);
			fp13_neg(h1, h1);
			fp_add(h1[0], h1[0], p->y);
			fp13_mul(l1, l1, h1);
			/*the final exponation*/
			pp_exp_bwk13(r, l1, s2);
		}
	}


	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep13_free(t1);
		ep13_free(t2);
		bn_free(a);


		fp13_free(l1);
       		fp13_free(l2);
        	fp13_free(l3);
        	fp13_free(l4);
       		fp13_free(l5);
       		fp13_free(l6);
		fp13_free(h1);
	}
}


