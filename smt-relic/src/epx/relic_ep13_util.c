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
 * Implementation of utilities for prime elliptic curves over 13-th
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
int ep13_is_infty(ep13_t p) {
	return (fp13_is_zero(p->z) == 1);
}
void ep13_set_infty(ep13_t p) {
	fp13_zero(p->x);
	fp13_zero(p->y);
	fp13_zero(p->z);
	p->coord = BASIC;
}

void ep13_copy(ep13_t r, ep13_t p) {
	fp13_copy(r->x, p->x);
	fp13_copy(r->y, p->y);
	fp13_copy(r->z, p->z);
	r->coord = p->coord;
}


void ep13_rand(ep13_t p) {
     ep13_curve_get_gen(p);
	
}

void ep13_print(ep13_t p) {
	fp13_print(p->x);
	fp13_print(p->y);
	fp13_print(p->z);
}


void ep13_rhs(fp13_t rhs, ep13_t p) {
	fp13_t t0;
	fp13_t t1;

	fp13_null(t0);
	fp13_null(t1);

	RLC_TRY {
		fp13_new(t0);
		fp13_new(t1);

		/* t0 = x1^2. */
		fp13_sqr(t0, p->x);
		/* t1 = x1^3. */
		fp13_mul(t1, t0, p->x);
		ep_curve_get_a();
              //  for(int i=0;i<13;i++){
                //   fp_mul_dig(t0[i], p->x[i],ep_curve_get_a()[0]);
		//}
		//fp13_add(t1, t1, t0);

		fp_add(t1[0], t1[0], ep_curve_get_b());

		fp13_copy(rhs, t1);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp13_free(t0);
		fp13_free(t1);
	}
}


int ep13_on_curve(ep13_t p) {
	ep13_t t;
	int r = 0;

	ep13_null(t);

	RLC_TRY {
		ep13_new(t);

		ep13_norm(t, p);

		ep13_rhs(t->x, t);
		fp13_sqr(t->y, t->y);

		r = (fp13_cmp(t->x, t->y) == RLC_EQ) || ep13_is_infty(p);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep13_free(t);
	}
	return r;
}

void ep13_tab(ep13_t *t, ep13_t p, int w) {
	if (w > 2) {
		ep13_dbl(t[0], p);
#if defined(EP_MIXED)
		ep13_norm(t[0], t[0]);
#endif
		ep13_add(t[1], t[0], p);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			ep13_add(t[i], t[i - 1], t[0]);
		}
#if defined(EP_MIXED)
		ep13_norm_sim(t + 1, t + 1, (1 << (w - 2)) - 1);
#endif
	}
	ep13_copy(t[0], p);
}



























