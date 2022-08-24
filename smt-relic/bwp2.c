
#include <stdio.h>
#include <stdlib.h>
#include "time.h"
#include "relic.h"
#include "relic_test.h"
#include "relic_bench.h"
#include "low/relic_fp_low.h"
int main(void) {
	core_init(); 
	fp_prime_init();
	ep_param_set_any_pairf();
        fp_param_print();
    	ep13_t q;
        ep_t p,r;
	fp13_t a, b, c, f;
	bn_t t;
	ep_curve_get_ord(t);
	ep13_rand(q);
	ep_curve_get_gen(p);
	ep_dbl(r,p);
	ep_norm(r,r);
	pp_map_sup_oatep_k13(f, p, q);
	fp13_sqr(f,f);
	printf("The first pairing is:\n");
	fp13_print(f);
	printf("*************************************************************\n");
	pp_map_sup_oatep_k13(f, r, q);
	printf("The second pairing is:\n");
	fp13_print(f);
	return 0;
}


