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
 * Implementation of configuration of prime elliptic curves over quadratic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* See ep/relic_ep_param.c for discussion of MAP_U parameters. */

/**
 * Parameters for a pairing-friendly prime curve over a quadratic extension.
 */
#if defined(EP_ENDOM) && FP_PRIME == 672
/** @{ */
#define GMT6_P672_AT		"0"
#define GMT6_P672_BT 	"4A00FFC87945FFD863087D885FCF07F7EAC908B14D3CC8AB1E2F2346A1F64E7F0AA4FEACE1055ADCD3E6D3F93D0033DC181F75A598AAAE7A792028768AAAAAE6BFD3D2FC55555556A3F6F0D3555555555B4F36E5"
#define GMT6_P672_XT		"2589B9848D2FEAFAF7E6C7605E48EBAB45AC69D071B3E918C7909F8EA12F94AAF8C84C8EA42C693C6A02DE57870D8F2ECED184E605AA9AD9A2E315C786F6C663321EA849ACAFA1872A55823247ECE3AD15E6EC0E"
#define GMT6_P672_YT		"3B04F58A2183CD1CA1F7C19BD54380D7C7F75F45E9878B6163B2C93670D756E6DA030B297D7E2741AE3B675D9835F2CB6A1EFF849FB367782DDA29F8E1AA8113A7203BA2B4D98CCFD31D16846A2336CBC3ED5410"
#define GMT6_P672_RT		"E0FFFFFFFFFFFFC400000000000003FF10000000000000200000000000000001"
#define GMT6_P672_HT		"A86665E80BFFFFD2C3C5D1DD5E0003142DC222D61AFFFE96A7A015A0000000248D1FF410B5555556741EA8CCAAAAAAAAB69ECD9B"
#define GMT6_P672_MAPUT   "15"
/** @} */
#endif
/**
 * Assigns a set of ordinary elliptic curve parameters.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 * @param[in] FIELD		- the finite field identifier.
 */
#define ASSIGN(CURVE)												\
	RLC_GET(str, CURVE##_AT, sizeof(CURVE##_AT));								\
	fp_read_str(a, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_BT, sizeof(CURVE##_BT));								\
	fp_read_str(b, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_XT, sizeof(CURVE##_XT));								\
	fp_read_str(g->x, str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_YT, sizeof(CURVE##_YT));								\
	fp_read_str(g->y, str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_RT, sizeof(CURVE##_RT));								\
	bn_read_str(r, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_HT, sizeof(CURVE##_HT));								\
	bn_read_str(h, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_MAPUT, sizeof(CURVE##_MAPUT));						\
	fp_read_str(u, str, strlen(str), 16);									\


/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
void ep_curve_set_twist(int type) {
	int ctmap = 0;
	char str[4 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	ep_t g;
	fp_t a, b, u;
	bn_t r, h;

	ep_null(g);
	fp_null(a);
	fp_null(b);
	fp_null(u);
	bn_null(r);
	bn_null(h);

	ctx->ep_is_twist = 0;
	if (type == RLC_EP_MTYPE || type == RLC_EP_DTYPE) {
		ctx->ep_is_twist = type;
	} else {
		return;
	}

	RLC_TRY {
		ep_new(g);
		fp_new(a);
		fp_new(b);
		fp_new(u);
		bn_new(r);
		bn_new(h);

		switch (ep_param_get()) {
#if FP_PRIME == 672
			case GMT6_P672:
				ASSIGN(GMT6_P672);
				break;
#endif
			default:
				(void)str;
				RLC_THROW(ERR_NO_VALID);
				break;
		}

		fp_zero(g->z);
		fp_set_dig(g->z, 1);
		g->coord = BASIC;
		ep_copy(ctx->ep_twist_g, g);
		fp_copy(ctx->ep_twist_a, a);
		fp_copy(ctx->ep_twist_b, b);
		//detect_opt(&(ctx->ep_twist_opt_a), ctx->ep_twist_a);
		//detect_opt(&(ctx->ep_twist_opt_b), ctx->ep_twist_b);
		bn_copy(&(ctx->ep_twist_r), r);
		bn_copy(&(ctx->ep_twist_h), h);
		
#if defined(WITH_PC)
		/* Compute pairing generator. */
		pc_core_calc();
#endif

//#if defined(EP_PRECO)
		//ep_twist_mul_pre((ep_t *)ep_twist_curve_get_tab(), ctx->ep_g);
//#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(g);
		fp_free(a);
		fp_free(b);
		fp_free(u);
		bn_free(r);
		bn_free(h);
	}
}
void ep_curve_twist_get_gen(ep_t g) {
	ep_copy(g, core_get()->ep_twist_g);
}
//void ep_curve_twist_get_a(fp_t a) {
		//fp_copy(a, core_get()->ep_twist_a);

//}
//void ep_curve_twist_get_b(fp_t b) {
			//fp_copy(b, core_get()->ep_twist_b);

//}
dig_t *ep_curve_twist_get_b(void) {
	return core_get()->ep_twist_b;
}
dig_t *ep_curve_twist_get_a(void) {
	return core_get()->ep_twist_a;
}