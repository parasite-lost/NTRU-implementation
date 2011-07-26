
#ifndef NTRU_TEST

#include "ntru.h"
#include "ntrulowlevel.h"
#include <gmp.h>


/* print polynomial to stdout
 * pol: polynomial
 * N: max degree bound
 */
void printPolynomial(int *pol, int N);

/* print big integer to stdout
 * number: big integer (gmp)
 */
void printMPZ(mpz_t *number);


int testlowlevel();

int testntru();

#define NTRU_TEST
#endif
