
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
        //fp13_init();
        fp_param_print();
        ep13_t q;
        fp13_t a;
	ep13_rand(q);
        fp13_mul(a, q->x, q->x);
        //fp13_frb(a, q->x, 1);
       // fp13_mul(a, q->x, q->y);
	fp13_neg(a, q->x);
        fp13_print(a);
	//fp13_sub(a, a,a);
        //fp13_print(a);
	return 0;
}


