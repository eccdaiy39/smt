
#include <stdio.h>
#include "relic.h"
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
#define BW13_P310_X0		"178a47400ee4844dcabab67b5e98725b53aa3e586942b53150a2c0b477d03aac76af0990ef259a"
#define BW13_P310_X1            "880d25ad347eddd9e6b4b77158a4a7d8ef8f6d01ad57af484c34b4173898af4c89eb0487eea7f"
#define BW13_P310_X2		"344a808a60e4782d23eef6532f0c248a401e8cf81d5bde0fcb57d3c5521e0947cf0800100e86fb"
#define BW13_P310_X3		"235c02e4c11b722f24c39ef24a30033ff5ac9b796ea5e9f286625fb0ee525e77c7969908baa518"
#define BW13_P310_X4		"1bb99869ee88cabdc1be15e609beef28cd8c6ee6553bb74befa418a4dd59f59d956636680dca80"
#define BW13_P310_X5		"2fa4cf220f50b19d5e51b64d72398ff75b56f564f9ebe87f676345e141c171b07f12ca31b9c2c9"
#define BW13_P310_X6		"2755a358a6a3a7f485d9615dd3a05d3ff996fa37bdc74cdb2c7307df952255953a57f21f7f0ce5"
#define BW13_P310_X7		"2c21b5c4e7afec04ea4899e9c7434559d6b4dbcfbe451c2ba1d02abf11f0e47b561ef8cb32d8a8"
#define BW13_P310_X8		"8d383aa56eeda988acaa9c8b1b431bf59826d953b5816fdae99aabd9786e935b321f9e6274830"
#define BW13_P310_X9		"1d592eb69a2f30063704706a79d3910dc0b58c04f747ebdf5432dd97ad27b6cf9bf2a6b1d0f736"
#define BW13_P310_X10		"16fb3fd23f01c425d56c24e72fdd10fe4457f84a49719854e0226db98ac44b14abf328810dcf32"
#define BW13_P310_X11		"26fb55a5e4ce39cb6d8e3d3c9ce40cce39955a327365a672978049429afa30d8adff45431d71e"
#define BW13_P310_X12		"38907f814588234a2bb95d48a2a1125524ff22e7e17d04ca6efa010b6107e0108bcd54c809c66"

#define BW13_P310_Y0		"de4f43428866897b2b753decbec30e135047b320e2d05bbcc9e925b5070ce944c9aa2a108a15c"
#define BW13_P310_Y1		"9a473da420eee242e26cd98c006917ff6ab34acb32a78d70799a301d1b7cb220d6c4bd3291794"
#define BW13_P310_Y2		"1d51157780b82e106700e17f63d15bfb5d5a85e6eaa128c97662ee37d42e88d9e8139498bcb3a7"
#define BW13_P310_Y3		"32eeef9d57af7fc682fa65b7cbb9ef0bd51a6ac201ac084d4029a2d5eb218cdc05ebda92d1ca39"
#define BW13_P310_Y4		"22297b9cc34987304a72989f3d4693edbbbbb3b3d5cd7867f5246caa8569a8284381810f6eb4b9"
#define BW13_P310_Y5		"2ba6e42b2b6dde629fd1301fffba648a56d31ff81b06993b8b554d896cb4454e290fd3201550f0"
#define BW13_P310_Y6		"1f2861c56e04fdc32947d7a1f9a8cfcd37ed1193e1c3b30b2456f704275bf74165e84e21a622f1"
#define BW13_P310_Y7		"1b94a0d344cfe00697b6f2c89043d38611ffb375d0f2f88d662b88702abe72d4d6c75921ef71bb"
#define BW13_P310_Y8		"1ff8863167fa7118490da4800c5fe30add32fa1c2a41acd19143518581f4cd606f8a6b985d54aa"
#define BW13_P310_Y9		"27fde64f25bd8ced914c35d6a5e089c9b22708b18291c14be3679499f008c5dc6a4117385e14ee"
#define BW13_P310_Y10		"b2cf79ade698ba7d9cecfa5be340121799c8ac812b3484d69c6427b0d56826827fa0e78f2b40c"
#define BW13_P310_Y11		"1e3378a6b8f782187956a62be562d6d409ec01e91698efa4a002e5cefcbe358787123b277ca9f0"
#define BW13_P310_Y12		"28f80bf8ed460676cfc30f86f93a31a787871591e5107a920cb41d0389046d38f37403f8b93661"

#define BW13_310_1     	    "157d04dfa056a8b2a9053f84cfa1ac0e03880ca1c6cab07fe529a2fbfef6f05ce8f8a167f7d846"
#define BW13_310_2	    "1a8e1e26d553c560a5baba93f5dd28c3833760fd7a60d67c18c6373f70666dd1330e675b311180"
#define BW13_310_3	    "312a12f76c074c6cd4a198c45caf37362e5b23ec2bbd82330b4c72152b4af954717aff8f116168"
#define BW13_310_4	    "34b3cda41746f6f434539c29ee61d1b232f19c4700af26a522a1b3ec513e1f1f67d1f8cd8f7d6a"
#define BW13_310_5	    "4cb736aa33d698f074a5fe8be347f27feff534abd19a72428c4eb3b3c62165bc8a5f06b04f754"
#define BW13_310_6	    "1c2f568d10671ff6b78be42ed05aa9e77ce8e53ecb07db37f107354bb3f79322288faef832e855"
#define BW13_310_7          "1dd082ecfc0b0d8502d8c0395ddbd4e3219860502c0476f5c405cfeb6f20408df535dca0eef5d7"
#define BW13_310_8	    "8f2eb7ca89ed4494407128642051dfa2b6f91cf067be552245196ac1f9959da25a1e736ae6996"
#define BW13_310_9	    "2b14448958c119a6eeaa1d4b4a9b433ffaa482020912313eba22c5ac9e59c5a6a4d6c98e92732a"
#define BW13_310_10	    "3222c860197a8d1a8b83684dc79ade654d369834403a78c22f2b714e73cf531491c98c0a96d86b"
#define BW13_310_11	    "8c7ecf4b10c4e44a2e28c58da119657c048b3fdf9907273df8abd8f9531eea1ab16afe9e9ec82"
#define BW13_310_12	    "3409ec1f50974886d976268a6e249b636388c20369ff78525ee9373f5d54b7070ce79622fdb207"
#define BW13_310_13         "35AB6E4E1F9062ABB4ED8DD22123887C4E8E8ADA95CD0470CEC0194D7B4B339766ECC91E5BA32C"



#define ASSIGN(CURVE)   \
    RLC_GET(str, CURVE##_X0, sizeof(CURVE##_X0));	                       \
    fp_read_str(g->x[0], str, strlen(str), 16);                  \
	RLC_GET(str, CURVE##_X1, sizeof(CURVE##_X1));              						\
	fp_read_str(g->x[1], str, strlen(str), 16);	                 \
	RLC_GET(str, CURVE##_X2, sizeof(CURVE##_X2));	           						\
	fp_read_str(g->x[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X3, sizeof(CURVE##_X3));							\
	fp_read_str(g->x[3], str, strlen(str), 16);							\
    RLC_GET(str, CURVE##_X4, sizeof(CURVE##_X4));							\
    fp_read_str(g->x[4], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X5, sizeof(CURVE##_X5));\
    fp_read_str(g->x[5], str, strlen(str), 16);	\
    RLC_GET(str, CURVE##_X6, sizeof(CURVE##_X6));							\
	fp_read_str(g->x[6], str, strlen(str), 16);	\
	RLC_GET(str, CURVE##_X7, sizeof(CURVE##_X7));			\
	fp_read_str(g->x[7], str, strlen(str), 16);                     \
	RLC_GET(str, CURVE##_X8, sizeof(CURVE##_X8));				\
	fp_read_str(g->x[8], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_X9, sizeof(CURVE##_X9));				\
	fp_read_str(g->x[9], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_X10, sizeof(CURVE##_X10));				\
	fp_read_str(g->x[10], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_X11, sizeof(CURVE##_X11));				\
	fp_read_str(g->x[11], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_X12, sizeof(CURVE##_X12));				\
	fp_read_str(g->x[12], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_Y0, sizeof(CURVE##_Y0));				\
	fp_read_str(g->y[0], str, strlen(str), 16);			\
	RLC_GET(str, CURVE##_Y1, sizeof(CURVE##_Y1));				\
	fp_read_str(g->y[1], str, strlen(str), 16);			\
	RLC_GET(str, CURVE##_Y2, sizeof(CURVE##_Y2));			\
	fp_read_str(g->y[2], str, strlen(str), 16);			   \
    RLC_GET(str, CURVE##_Y3, sizeof(CURVE##_Y3));			\
	fp_read_str(g->y[3], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_Y4, sizeof(CURVE##_Y4));				\
	fp_read_str(g->y[4], str, strlen(str), 16);			             \
	RLC_GET(str, CURVE##_Y5, sizeof(CURVE##_Y5));						\
	fp_read_str(g->y[5], str, strlen(str), 16);                                              \
	RLC_GET(str, CURVE##_Y6, sizeof(CURVE##_Y6));					        \
	fp_read_str(g->y[6], str, strlen(str), 16);				\
	RLC_GET(str, CURVE##_Y7, sizeof(CURVE##_Y7));                                                             \
	fp_read_str(g->y[7], str, strlen(str), 16);                                                 \
 	RLC_GET(str, CURVE##_Y8, sizeof(CURVE##_Y8));	                                      \
 	fp_read_str(g->y[8], str, strlen(str), 16);	                                            \
 	RLC_GET(str, CURVE##_Y9, sizeof(CURVE##_Y9));                         \
	fp_read_str(g->y[9], str, strlen(str), 16);	             				\
	RLC_GET(str, CURVE##_Y10, sizeof(CURVE##_Y10));	               					\
	fp_read_str(g->y[10], str, strlen(str), 16);	       \
	RLC_GET(str, CURVE##_Y11, sizeof(CURVE##_Y11));	               					\
	fp_read_str(g->y[11], str, strlen(str), 16);\
	RLC_GET(str, CURVE##_Y12, sizeof(CURVE##_Y12));	               					\
	fp_read_str(g->y[12], str, strlen(str), 16);                                  					 	


#define ASSIGNFRB(FIELD)												\
	RLC_GET(str,FIELD##_1, sizeof(FIELD##_1));								\
	fp_read_str(a[0], str, strlen(FIELD##_1),16);\
	RLC_GET(str,FIELD##_2, sizeof(FIELD##_2));								\
    fp_read_str(a[1], str,strlen(FIELD##_2),16);\
	RLC_GET(str,FIELD##_3, sizeof(FIELD##_3));								\
	fp_read_str(a[2], str, strlen(FIELD##_3),16);\
	RLC_GET(str,FIELD##_4, sizeof(FIELD##_4));	\
	fp_read_str(a[3], str, strlen(FIELD##_4),16);\
	RLC_GET(str,FIELD##_5, sizeof(FIELD##_5));								\
	fp_read_str(a[4], str, strlen(FIELD##_5),16);\
	RLC_GET(str,FIELD##_6, sizeof(FIELD##_6));								\
	fp_read_str(a[5], str, strlen(FIELD##_6),16);\
	RLC_GET(str,FIELD##_7, sizeof(FIELD##_7));						\
	fp_read_str(a[6], str, strlen(FIELD##_7),16);\
	RLC_GET(str,FIELD##_8, sizeof(FIELD##_8));								\
	fp_read_str(a[7], str, strlen(FIELD##_8),16);\
	RLC_GET(str,FIELD##_9, sizeof(FIELD##_9));								\
	fp_read_str(a[8], str, strlen(FIELD##_9),16);\
	RLC_GET(str,FIELD##_10, sizeof(FIELD##_10));								\
	fp_read_str(a[9], str, strlen(FIELD##_10),16);\
	RLC_GET(str,FIELD##_11, sizeof(FIELD##_11));								\
	fp_read_str(a[10], str, strlen(FIELD##_11),16);\
	RLC_GET(str,FIELD##_12, sizeof(FIELD##_12));								\
	fp_read_str(a[11], str, strlen(FIELD##_12),16);\
	RLC_GET(str,FIELD##_13, sizeof(FIELD##_13));		     \
	fp_read_str(sr3, str, strlen(FIELD##_13),16);    \
/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/
 void ep13_curve_set(){
    char str[2 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	fp_t sr3;
	fp13_t a;
	ep13_t g;
	fp_null(sr3);
	fp13_null(a);
	ep13_null(g);
	RLC_TRY {
		fp_new(sr3);
		fp13_new(a);
		ep13_new(g);
		ASSIGN(BW13_P310);
		fp13_zero(g->z);
		fp_set_dig(g->z[0], 1);
		g->coord = BASIC;
		ep13_copy(&(ctx->ep13_g), g);
		
		ASSIGNFRB(BW13_310);
		fp_copy(ctx->sr3, sr3);
		fp13_copy(ctx->frb13_1, a);
		for(int i=0;i<12;i++){
			fp_mul(ctx->frb13_2[i], ctx->frb13_1[i], a[i]);
            fp_mul(ctx->frb13_3[i], ctx->frb13_2[i], a[i]);
            fp_mul(ctx->frb13_4[i], ctx->frb13_3[i], a[i]);
            fp_mul(ctx->frb13_5[i], ctx->frb13_4[i], a[i]);
            fp_mul(ctx->frb13_6[i], ctx->frb13_5[i], a[i]);
            fp_mul(ctx->frb13_7[i], ctx->frb13_6[i], a[i]);
            fp_mul(ctx->frb13_8[i], ctx->frb13_7[i], a[i]);
            fp_mul(ctx->frb13_9[i], ctx->frb13_8[i], a[i]);
            fp_mul(ctx->frb13_10[i], ctx->frb13_9[i], a[i]);
            fp_mul(ctx->frb13_11[i], ctx->frb13_10[i], a[i]);
            fp_mul(ctx->frb13_12[i], ctx->frb13_11[i], a[i]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(sr3);
		ep13_free(g);
		fp13_free(a);
	}
}				

				
void ep13_curve_get_gen(ep13_t g) {
	ep13_copy(g, &(core_get()->ep13_g));
}


