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
 * Implementation of the Miller doubling function.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_qpl_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2, ep13_t q, ep_t p, ep_t p2) {
	fp13_t t0, tt0, t1, t2, t3, t4, t5;
	dv13_t u0, u1, u2;
	ep13_t _q;
	fp13_null(t0);
	fp13_null(tt0);
	fp13_null(t1);
	fp13_null(t2);
	fp13_null(t3);
	fp13_null(t4);
	fp13_null(t5);
	dv13_null(u0);
	dv13_null(u1);
	dv13_null(u2);

	RLC_TRY {
		fp13_new(t0);
		fp13_new(tt0);
		fp13_new(t1);
		fp13_new(t2);
		fp13_new(t3);
		fp13_new(t4);
		dv13_new(u0);
		dv13_new(u1);
		dv13_new(u2);
		ep13_copy(_q,q);
		
		/*compute [4]*q and q<-[4]*q*/

		//doubling point 
		fp13_sqr(t0, _q->x);
		fp13_hlv(t1, t0);
		fp13_addn_low(t0, t0, t1);
		fp13_sqr(t1, t0);
		fp13_sqr(t2, _q->y);
		fp13_mul(t3, _q->x, t2);
		fp13_dbl(t4, t3);
		fp13_sub(_q->x, t1, t4);

		fp13_mul(_q->z, _q->y, _q->z);

		fp13_sub(t1, t3, _q->x);
		fp13_muln_low(u0, t0, t1);
		fp13_sqrn_low(u1, t2);
		fp13_subc_low(u0, u0, u1);
		fp13_rdc(_q->y, u0);
		
		//quadrupling point
		fp13_sqr(tt0, _q->x);
		fp13_hlv(t1, tt0);
		fp13_addn_low(tt0, tt0, t1);//
		fp13_sqr(t1, tt0);
		fp13_sqr(t2, _q->y);//
		fp13_mul(t3, _q->x, t2);//
		fp13_dbl(t4, t3);
		fp13_sub(q->x, t1, t4);
		fp13_mul(q->z, _q->y, _q->z);

		fp13_sub(t1, t3, q->x);
		fp13_muln_low(u0, tt0, t1);
		fp13_sqrn_low(u1, t2);
		fp13_subc_low(u0, u0, u1);
		fp13_rdc(q->y, u0);
		
        	/*line functions*/
		fp13_sqr(t1, _q->z);
		fp13_mul(t3, t1, q->z);
		for(int i = 0; i < 13; i++)fp_muln_low(u0[i], t3[i], p->y);//deta1
		for(int i = 0; i < 13; i++)fp_mul(t4[i], t1[i], p->x);
		for(int i = 0; i < 13; i++)fp_mul(t5[i], t1[i], p2->x);
		fp13_sub(t4, t4, _q->x);//deta2
		fp13_sub(t5, t5, _q->x);

		fp13_mul(t0, t0, _q->y);
		fp13_muln_low(u1, t0, t4);//-T
		fp13_muln_low(u2, tt0, t4);//2T
		fp13_addc_low(u1, u0, u1);
		fp13_subc_low(u2, u0, u2);
		fp13_rdc(t1, u1);
		fp13_rdc(t4, u2);
		fp13_sub(g1, t1, t2);
		fp13_sub(f1, t4, t2);
		fp13_mul(f1, f1, t3);



		fp13_muln_low(u1, t0, t5);//-T
		fp13_muln_low(u2, tt0, t5);//2T
		fp13_addc_low(u1, u0, u1);
		fp13_subc_low(u2, u0, u2);
		fp13_rdc(t1, u1);
		fp13_rdc(t4, u2);
		fp13_sub(g2, t1, t2);
		fp13_sub(f2, t4, t2);
		fp13_mul(f2, f2, t3);
               
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(t0);
		fp13_free(tt0);
		fp13_free(t1);
		fp13_free(t2);
		fp13_free(t3);
		fp13_free(t4);
		fp13_free(t5);  


		dv13_free(u0);
		dv13_free(u1);
		dv13_free(u2);
	}
}

void pp_dba_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2,  ep13_t r, ep13_t q, ep_t p, ep_t p2) {
	fp13_t t0, tt0, t1, tt1, t2, t3, t4, t5;
	dv13_t u0, u1, u2;
	ep13_t _q;
	fp13_null(t0);
	fp13_null(tt0);
	fp13_null(t1);
	fp13_null(tt1);
	fp13_null(t2);
	fp13_null(t3);
	fp13_null(t4);
	fp13_null(t5);
	dv13_null(u0);
	dv13_null(u1);
	dv13_null(u2);

	RLC_TRY {
		fp13_new(t0);
		fp13_new(tt0);
		fp13_new(t1);
		fp13_new(tt1);
		fp13_new(t2);
		fp13_new(t3);
		fp13_new(t4);
		fp13_new(t5);
		dv13_new(u0);
		dv13_new(u1);
		dv13_new(u2);
		ep13_copy(_q,r);
		
		/*compute [2]*q and q<-[2]*q+r*/

		//doubling point 
		fp13_sqr(t0, _q->x);
		fp13_hlv(t1, t0);
		fp13_addn_low(t0, t0, t1);//
		fp13_sqr(t1, t0);
		fp13_sqr(t2, _q->y);
		fp13_mul(t3, _q->x, t2);
		fp13_dbl(t4, t3);
		fp13_sub(_q->x, t1, t4);
		fp13_mul(_q->z, _q->y, _q->z);

		fp13_sub(t1, t3, _q->x);
		fp13_muln_low(u0, t0, t1);
		fp13_sqrn_low(u1, t2);
		fp13_subc_low(u0, u0, u1);
		fp13_rdc(_q->y, u0);
		
		//addition point

		fp13_sqr(t5, _q->z);//
		fp13_mul(tt1, _q->z, t5);  
		fp13_mul(t2, tt1, q->y);	
		fp13_sub(t1, t2, _q->y);//a
		fp13_mul(tt0, t5, q->x);
		fp13_sub(tt0, tt0, _q->x);//b
		fp13_sqr(t2, tt0);//b^2
		fp13_mul(t3, t2, tt0);//b^3
		fp13_sqr(t4, t1);//a^2
		fp13_sub(t4, t4, t3);
		fp13_mul(t2, _q->x, t2);
		fp13_dbl(r->x, t2);
		fp13_sub(r->x, t4, r->x);

		fp13_muln_low(u0, _q->y, t3);
		fp13_sub(t2, t2, r->x);
		fp13_muln_low(u1, t2, t1);
		fp13_subc_low(u1, u1, u0);
		fp13_rdc(r->y, u1);
		fp13_mul(r->z, _q->z, tt0);
	
		/*line functions*/
	
		for(int i = 0; i < 13; i++)fp_mul(t2[i], tt1[i], p->y);
		fp13_sub(t2, t2, _q->y);
		fp13_muln_low(u0, tt0, t2);//deta1
		for(int i = 0; i < 13; i++)fp_mul(t2[i], t5[i], p->x);
		fp13_sub(t2, t2, _q->x);//deta2
		fp13_muln_low(u1, t1, t2);
		fp13_subc_low(u1, u0, u1);
		fp13_rdc(f1, u1);

		fp13_mul(t0, t0, tt0);
		fp13_muln_low(u1,t0, t2);
		fp13_addd_low(u1, u0, u1);
		fp13_rdc(g1, u1);



		for(int i = 0; i < 13; i++)fp_mul(t2[i], t5[i], p2->x);
		fp13_sub(t2, t2, _q->x);//deta2
		fp13_muln_low(u1, t1, t2);
		fp13_subc_low(u1, u0, u1);
		fp13_rdc(f2, u1);

		fp13_muln_low(u1, t0, t2);
		fp13_addd_low(u1, u0, u1);
		fp13_rdc(g2, u1);

		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(t0);
		fp13_free(tt0);
		fp13_free(tt1);
		fp13_free(t1);
		fp13_free(t2);
		fp13_free(t3);
		fp13_free(t4);
		fp13_free(t5);

		dv13_free(u0);
		dv13_free(u1);
		dv13_free(u2);
	}
}



void pp_add_k13_projc_lazyr(fp13_t f1, fp13_t g1, fp13_t f2, fp13_t g2, ep13_t r, ep13_t q, ep_t p, ep_t p2) {
	fp13_t t0, tt0, tt1, t1, t2, t3, t4;
	dv13_t u0, u1;
	ep13_t _r;
	
	fp13_null(t0);
	fp13_null(tt0);
	fp13_null(t1);
	fp13_null(tt1);
	fp13_null(t2);
	fp13_null(t3);
	fp13_null(t4);
	dv13_null(u0);
	dv13_null(u1);


	RLC_TRY {
		fp13_new(t0);
		fp13_null(tt0);
		fp13_new(t1);
		fp13_null(tt1);
		fp13_new(t2);
		fp13_new(t3);
		fp13_new(t4);
		dv13_new(u0);
		dv13_new(u1);
		ep13_copy(_r, r);
		
		/*compute q + r and r <- q + r */

		fp13_sqr(t0, r->z);
		fp13_mul(tt1, r->z, t0);  
		fp13_mul(t2, tt1, q->y);	
		fp13_sub(t1, t2, r->y);//sita
		fp13_mul(tt0, t0, q->x);
		fp13_sub(tt0, tt0, r->x);//lambda
		fp13_sqr(t2, tt0);//lambda^2
		fp13_mul(t3, t2, tt0);//lambda^3
		fp13_sqr(t4, t1);
		fp13_sub(t4, t4, t3);
		fp13_mul(t2, r->x, t2);
		fp13_dbl(r->x, t2);
		fp13_sub(r->x, t4, r->x);


		fp13_muln_low(u0, r->y, t3);
		fp13_sub(t2, t2, r->x);
		fp13_muln_low(u1, t2, t1);
		fp13_subc_low(u1, u1, u0);
		fp13_rdc(r->y, u1);
		fp13_mul(r->z, r->z, tt0);
		/*compute the line functions*/
		for(int i = 0; i < 13; i++)fp_mul(tt1[i], tt1[i], p->y);
		fp13_sub(tt1, tt1, _r->y);
		fp13_muln_low(u0, tt0, tt1);

		for(int i = 0; i < 13; i++)fp_mul(t2[i], t0[i], p->x);
		fp13_sub(t2, t2, _r->x);
		fp13_muln_low(u1, t2, t1);
		fp13_subc_low(u1, u0, u1);
		fp13_rdc(f1, u1);
		fp13_mul(g1, t2, r->z);


		for(int i = 0; i < 13; i++)fp_mul(t0[i], t0[i], p2->x);
		fp13_sub(t0, t0, _r->x);
		fp13_muln_low(u1, t0, t1);
		fp13_subc_low(u0, u0, u1);
		fp13_rdc(f2, u0);
		fp13_mul(g2, t0, r->z);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp13_free(t0);
	        fp13_free(tt0);
		fp13_free(t1);
	        fp13_free(tt1);
		fp13_free(t2);
		fp13_free(t3);
		fp13_free(t4);
		fp13_free(t5);
		fp13_free(t6);
		dv2_free(u0);
		dv2_free(u1);
	}
}




