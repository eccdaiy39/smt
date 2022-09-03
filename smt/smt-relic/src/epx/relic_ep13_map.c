#include <stdio.h>
#include "relic.h"
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
 * Implementation of hashing to a prime elliptic curve over a 13-th
 * extension.
 *
 * @ingroup epx
 */
/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/
static void ep13_sw_bw(ep13_t p, const fp_t t) {
	fp_t u0,  srm3;
    fp13_t t0, t1, t2, t3, t4, t5;
	int a1, a2, a3;
     fp_null(u0);
	 fp_null(srm3);
     fp13_null(t0);
     fp13_null(t1);
	 fp13_null(t2);
     fp13_null(t3);
	
  
     RLC_TRY {
 		 fp_new(u0);
	 	 fp_new(srm3);
         fp13_new(t0);
         fp13_new(t1);
         fp13_new(t2);
		 fp13_new(t3);

		 fp13_zero(t0);
		 fp_copy(t0[1], t);
         fp13_sqr(t3, t0);
         fp_add(t3[0], t3[0], ep_curve_get_b());
         fp_add_dig(t3[0], t3[0], 1);
		 fp13_inv(t3, t3);
		 fp_copy(srm3, core_get()->sr3);
         fp_sub_dig(u0, srm3, 1);
         fp_hlv(u0, u0);//j

		 fp13_mul(t3, t3, t0);
         for(int i=0; i<13; i++)fp_mul(t3[i], t3[i], srm3);//w
		 fp13_mul(t1, t0, t3);
		 fp13_neg(t1, t1);
		 fp_add(t1[0], t1[0], u0);
		 fp13_neg(t2, t1);
		 fp_sub_dig(t2[0], t2[0], 1);
		 fp13_sqr(t3, t3);
		 fp13_inv(t3, t3);
		 fp_add_dig(t3[0], t3[0], 1);
		 fp13_sqr(t0, t1);
		 fp13_mul(t0, t0, t1);
		 fp_add(t0[0], t0[0], ep_curve_get_b());

		 fp13_sqr(t4, t2);
		 fp13_mul(t4, t4, t2);
		 fp_add(t4[0], t4[0], ep_curve_get_b());
        
		
		fp_rand(u0);
		 fp_sqr(u0, u0);
		 for(int i=0; i<13; i++)fp_mul(t5[i], t0[i], u0);
		 a1=fp13_is_square(t0);
		fp_rand(u0);
		 fp_sqr(u0, u0);
		 for(int i=0; i<13; i++)fp_mul(t5[i], t4[i], u0);
		 a2=fp13_is_square(t4);
		 a3=(a1-1)*a2;
		 a3= a3 % 3;
		 if(a3 < 0)a3 = a3 + 3;
		 a3=a3 +1;
		 switch(a3){
			 case 1:
			 	fp13_copy(p->x, t1);
			 	fp13_srt(p->y, t0);
				fp_rand(u0);
		 		fp_sqr(u0, u0);
				 fp_mul(u0, u0, t);
				 if(!fp_srt(u0, u0))fp13_neg(p->y, p->y);
				fp13_zero(p->z);
          		fp_set_dig(p->z[0], 1);
                break;
			case 2:
			 	fp13_copy(p->x, t2);
			 	fp13_srt(p->y, t4);
				 fp_sqr(u0, u0);
				 fp_mul(u0, u0, t);
				 if(!fp_srt(u0, u0))fp13_neg(p->y, p->y);
				fp13_zero(p->z);
          		fp_set_dig(p->z[0], 1);
				break;
			case 3:
				fp13_copy(p->x, t3);
			    fp13_sqr(t0, t3);
		        fp13_mul(t3, t0, t3);
		        fp_add(t3[0], t3[0], ep_curve_get_b());
			 	fp13_srt(p->y, t3);
				 fp_sqr(u0, u0);
				 fp_mul(u0, u0, t);
				 if(!fp_srt(u0, u0))fp13_neg(p->y, p->y);
				fp13_zero(p->z);
          		fp_set_dig(p->z[0], 1); 
				break;

		 }
     }
     RLC_CATCH_ANY {
         RLC_THROW(ERR_CAUGHT);
     }
     RLC_FINALLY {
     	fp_free(u0);
		fp_free(srm3);
     	fp13_free(t0);
     	fp13_free(t1);
	 	fp13_free(t2);
     	fp13_free(t3);
     }
 }
  
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
 void ep13_map(ep13_t p, const uint8_t *msg, int len) {
     bn_t k, pm1o2;
     fp_t t;
     uint8_t digest[RLC_MD_LEN];
     bn_null(k);
     bn_null(pm1o2);
     fp_null(t);
  
     RLC_TRY {
         bn_new(k);
         bn_new(pm1o2);
         fp_new(t);
         pm1o2->sign = RLC_POS;
         pm1o2->used = RLC_FP_DIGS;
         dv_copy(pm1o2->dp, fp_prime_get(), RLC_FP_DIGS);
         bn_hlv(pm1o2, pm1o2);
         md_map(digest, msg, len);
         bn_read_bin(k, digest, RLC_MIN(RLC_FP_BYTES, RLC_MD_LEN));
         fp_prime_conv(t, k);
         ep13_sw_bw(p, t);
		 //ep13_cof(p, p);
     }
     RLC_CATCH_ANY {
         RLC_THROW(ERR_CAUGHT);
     }
     RLC_FINALLY {
         bn_free(k);
         bn_free(pm1o2);
         fp_free(t);
     }
 }