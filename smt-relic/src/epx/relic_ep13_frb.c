/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of frobenius action on prime elliptic curves over
 * quartic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep13_psi(ep13_t r, ep13_t p, int i) {
    fp_t t0;
	ep13_copy(r, p);
    fp_sqr(t0, ep_curve_get_beta());
	fp13_frb(r->x, r->x, i);
	fp13_frb(r->y, r->y, i);
	fp13_frb(r->z, r->z, i);
    if(i%3 == 1)for(int j= 0; j<13; j++)fp_mul(r->x[j],r->x[j], t0);
    if(i%3 == 2)for(int j= 0; j<13; j++)fp_mul(r->x[j],r->x[j], ep_curve_get_beta());
}
void ep13_frb(ep13_t r, ep13_t p, int i) {
	fp13_frb(r->x, p->x, i);
	fp13_frb(r->y, p->y, i);
	fp13_frb(r->z, p->z, i);
}
