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
 * Implementation of the final exponentiation for pairings over prime curves.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"


void pp_exp_bwk13(fp13_t c, fp13_t l1, fp13_t l2) {
	fp13_t t, a1, t0_num,t0_den,t10_num, t10_den, t11_num, t11_den, t12_num, t12_den;
	bn_t x;
	bn_null(x);
	fp13_null(t0_num);
	fp13_null(t0_den);
	fp13_null(t10_num);
	fp13_null(t10_den);
	fp13_null(t11_num);
	fp13_null(t11_den);
	fp13_null(t2_num);
	fp13_null(t12_den);
	RLC_TRY {
	        bn_new(x);
		fp13_new(t);
		fp13_new(a1);
		fp13_new(t0_num);
	        fp13_new(t0_den);
	        fp13_new(t10_num);
	        fp13_new(t10_den);
	        fp13_new(t11_num);
	        fp13_new(t11_den);
	        fp13_new(t2_num);
	        fp13_new(t12_den);

		fp_prime_get_par(x);
                bn_neg(x,x);
		/*a1 = a^(p-1)*/
		fp13_frb(t, l1, 1);
		fp13_frb(a1, l2, 1);
		fp13_mul(t, t, l2);
		fp13_mul(a1, a1, l1);
		fp13_inv(a1, a1);
		fp13_mul(a1, a1, t);
	
		/*compute a^(x^i) for i=1,2,3,4,5*/
		fp13_exp(t0_den, a1, x);//x
		fp13_exp(t11_num, t0_den, x);//x^2=t0_num
		fp13_exp(t10_den, t11_num, x);//x^3
		fp13_exp(t11_den, t10_den, x);//x^4
		fp13_exp(t10_num, t11_den, x);//x^5

		/*add x^i(i <= 5) t0 t_i_den and t_i_num*/
		fp13_mul(t12_num, t0_den, a1);//x+1
		fp13_mul(t12_den, t0_den, t10_den);//x+x^3
		fp13_sqr(t0_den, t12_num);//2x+2

		fp13_sqr(t, t11_num);
		fp13_sqr(t, t);//4*x^2
		fp13_mul(t12_num, t12_num, t);
		fp13_mul(t, t11_den, t10_den);//x^3+x^4
		fp13_mul(t11_den, t12_den, t);
		fp13_sqr(t10_den, t);

                /*compute t = a1^(x^14+x^13+x^12)*/
		fp13_mul(t, t10_num, t);
		for(int i = 0; i<9; i++)fp13_exp(t,t,x);
	
		/*compute t0_den, t0_num, t10_den, t10_num, t11_den, t11_num, t12_den, t12_num*/
		fp13_mul(t0_num, t11_num, t);
		fp13_exp(t, t, x);
		fp13_mul(t0_num, t0_num, t);

		fp13_exp(t12_den, t, x);
		fp13_mul(t11_den, t11_den, t12_den);
	        
		fp13_exp(t, t12_den, x);
		fp13_mul(t10_num, t10_num, t);
		fp13_exp(t, t, x);
		fp13_mul(t10_num, t10_num, t);

		/*compute t= a1^(t10 + t11*p + t12*p^2)*/	
		fp13_frb(t11_den, t11_den, 1);	
		fp13_frb(t11_num, t11_num, 1);	
		fp13_frb(t12_den, t12_den, 2);	
		fp13_frb(t12_num, t12_num, 2);
		
		fp13_mul(t10_den, t10_den, t11_den);
		fp13_mul(t10_den, t10_den, t12_den);

		fp13_mul(t10_num, t10_num, t11_num);
		fp13_mul(t10_num, t10_num, t12_num);

		fp13_inv_uni(t10_num, t10_num);
		fp13_mul(t, t10_den, t10_num);
		
		/*compute t^(x^3),t^(x^6), t^(x^9)*/
		fp13_exp(t10_den, t, x);
		fp13_exp(t10_den, t10_den, x);
		fp13_exp(t10_den, t10_den, x);

		fp13_exp(t11_den, t10_den, x);
		fp13_exp(t11_den, t11_den, x);
		fp13_exp(t11_den, t11_den, x);

		fp13_exp(t12_den, t11_den, x);
		fp13_exp(t12_den, t12_den, x);
		fp13_exp(t12_den, t12_den, x);

		/*t^((x^9+3)*p + x^6*p^4 + x^3*p^7 + p^10)*/
		fp13_frb(t, t, 10);
		fp13_frb(t10_den, t10_den, 7);
		fp13_frb(t11_den, t11_den, 4);

		fp13_sqr(t12_num, a1);
		fp13_mul(t12_num, t12_num, a1);
		fp13_mul(t12_den, t12_den, t12_num);
		fp13_frb(t12_den, t12_den, 1);

		fp13_mul(t, t, t10_den);
		fp13_mul(t, t, t11_den);
		fp13_mul(t, t, t12_den);

		/*the last setp of exp: t0*t*/
		fp13_inv_uni(t0_num, t0_num);
		fp13_mul(t, t, t0_num);
		fp13_mul(c, t, t0_den);
		
		
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp13_free(t);
		fp13_free(a1);
		fp13_free(t0_num);
		fp13_free(t0_den);
		fp13_free(t10_num);
		fp13_free(t10_den);
		fp13_free(t11_num);
		fp13_free(t11_den);
		fp13_free(t2_num);
		fp13_free(t12_den);
	}

}





