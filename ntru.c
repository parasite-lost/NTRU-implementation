#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "ntru.h"
#include "ntrulowlevel.h"
#include <time.h>
#include <gmp.h>



/* modulo operation that only returns positive values 
 * returns: k mod N
 */
int32_t mod(int32_t k, int32_t N);

/* divide a polynomial by x in Z[x]/(x^N - 1) (i.e. cyclic shift)
 * remark: this will only be called in this context with
 * polynomial[0] == 0
 * polynomial: polynomial which will be divided by x
 * N: max degree bound
 */
void PolDivX(int32_t *polynomial, int32_t N);


void NTRU_GenKeys(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength, int32_t N, int32_t p, int32_t q0, int32_t r, int32_t d_f, int32_t d_g, int32_t d)
{
	int32_t q = fastExp(q0, r);
	/* allocate memory for all needed polynomials
	 * keys */
	int32_t *f = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *h = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *g = (int32_t*)malloc(N * sizeof(int32_t));
	/* almost inverse polynomials of f */
	int32_t *F_p = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *F_q = (int32_t*)malloc(N * sizeof(int32_t));
	/* random polynomial f with d_f coefficients = 1, d_f coeffitients = -1, remaining = 0 
	 * random polynomial g with d_g coefficients = 1 and = -1, remaining = 0 */
	RandomTriPolynomial(&f, d_f, d_f - 1, N);
	RandomTriPolynomial(&g, d_g, d_g, N);
	/* compute the inverse modulo p, second part of private key 
	 * TODO: test if this really exists ? */
	InversePolynomialMod(&F_p, f, N, p);
	/* compute the inverse modulo q = q0^r */
	InversePolynomialMod_r(&F_q, f, N, q0, r);
	/* compute public key h = F_q * g */
	cyclicConvolutionMod(h, F_q, g, N, q);
	
	/* write private and public key */
	writePrivate(privatekey, privlength, f, F_p, N, p, q);
	writePublic(publickey, publength, h, N, p, q, d);




	/* TODO: fix length */
	/* clean up */
	free(f);
	free(h);
	free(g);
	free(F_p);
	free(F_q);
	return;
}

void NTRU_GenKeys_HighSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength)
{
	NTRU_GenKeys(privatekey, privlength, publickey, publength, 503, 3, 2, 8, 216, 72, 55);
	return;
}
void NTRU_GenKeys_MediumSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength)
{
	NTRU_GenKeys(privatekey, privlength, publickey, publength, 167, 3, 2, 7, 61, 20, 18);
	return;
}

void NTRU_GenKeys_LowSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength)
{
	NTRU_GenKeys(privatekey, privlength, publickey, publength, 107, 3, 2, 6, 15, 12, 5);
	return;
}



void NTRU_Encrypt_Init(NTRU_Encrypt_ctx *e_ctx, uint8_t *publickey)
{
	/* init context */
	readPublic(e_ctx, publickey);
	e_ctx->base3_currentBits = 0;
	e_ctx->base3_bits = 0;
	e_ctx->base3_trailing = 0;
	e_ctx->coefficients = (int32_t*)malloc(e_ctx->N * sizeof(int32_t));
	e_ctx->coefficientCount = 0;
	return;
}


void NTRU_Decrypt_Init(NTRU_Decrypt_ctx *d_ctx, uint8_t *privatekey)
{
	readPrivate(d_ctx, privatekey);
	d_ctx->base3_bits = 0;
	d_ctx->base3_currentBits = 0;
	d_ctx->base3_trailing = 0;
	d_ctx->coefficients = NULL;
	d_ctx->coefficientCount = 0;
	return;
}

void freeContainer(NTRU_Container *con, int32_t num)
{
	int32_t i;
	for(i = 0; i < num; i++)
	{
		if(con[i].polynomial != NULL)
			free(con[i].polynomial);
	}
	free(con);
	return;
}

void freeEncrypt_ctx(NTRU_Encrypt_ctx *e_ctx)
{
	if(e_ctx->h != NULL)
	{
		free(e_ctx->h);
	}
	if(e_ctx->coefficients != NULL)
	{
		free(e_ctx->coefficients);
	}
	return;
}

void freeDecrypt_ctx(NTRU_Decrypt_ctx *d_ctx)
{
	if(d_ctx->f != NULL)
		free(d_ctx->f);
	if(d_ctx->F_p != NULL)
		free(d_ctx->F_p);
	if(d_ctx->coefficients != NULL)
		free(d_ctx->coefficients);
	return;
}



int32_t fastExp(int32_t b, int32_t e)
{
	int32_t ret = 1;
	int32_t ee = e, bb = b;
	while(ee > 0)
	{
		if(ee % 2 != 0) ret *= bb;
		bb *= bb;
		ee /= 2;
	}
	return ret;
}

void RandomTriPolynomial(int32_t **polynomial, int32_t d1, int32_t d2, int32_t N)
{
	int32_t coeff, i; /* coefficient and counter variable */
	int32_t *pol = *polynomial; 
	/* initalize random number generator */
	srandom(time(NULL));
	
	/* initialize polynomial with 0-coefficients */
	for(i = 0; i < N; i++)
		pol[i] = 0;

	/* randomly set d1 coefficients to 1 */
	coeff = random()%N;
	for(i = 0; i < d1; i++)
	{
		/* coefficient already set to 1? -> choose new coefficient */
		while(pol[coeff] != 0)
			coeff = random()%N;
		pol[coeff] = 1;
	}
	
	/* randomly set d2 coefficients to -1 */
	for(i = 0; i < d2; i++)
	{
		/* coefficient already set to 1 or -1? -> choose new coefficient */
		while(pol[coeff] != 0)
			coeff = random()%N;
		pol[coeff] = -1;
	}
	return;
}


void InversePolynomialMod(int32_t **inverse, int32_t *polynomial, int32_t N, int32_t prime)
{
	if(prime == 2)
	{
		InversePolynomialMod2(inverse, polynomial, N);
		return;
	}
	if(prime == 3)
	{
		InversePolynomialMod3(inverse, polynomial, N);
		return;
	}
	/* TODO: other prime than 2 or 3 */
	return;
}

void InversePolynomialMod2(int32_t **inverse, int32_t *polynomial, int32_t N)
{
	int32_t k, i; /* counter */
	int32_t *b, *f, *c, *g, *tmp; /* polynomials */
	int32_t degf, degg, degtmp; /* degree of polynomials */
	int32_t *ret = *inverse; /* return */
	b = (int32_t *)malloc(sizeof(int32_t) * N);
	f = (int32_t *)malloc(sizeof(int32_t) * N);
	c = (int32_t *)malloc(sizeof(int32_t) * N);
	g = (int32_t *)malloc(sizeof(int32_t) * N);

	/* init */
	for(i = 0; i < N; i++)
	{
		b[i] = 0;
		f[i] = 0;
		c[i] = 0;
		g[i] = 0;
	}
	
	k = 0;
	b[0] = 1;
	/* c[0] = 0 */
	/* first loop pass: swap b and c (step 7 )
	 *                  b(x) = b(x) + c(x) (step 9)
	 *                  -> b(x) = c(x) = 1 
	 *                  -> no swap, init b[0] = 1 and c[0] = 1 
	 */
	c[0] = 1;
	/* first loop pass: swap f and g (step 7)
	 *                  f(x) = f(x) + g(x) (step 8)
	 *                  -> init g instead of f
	 */
	degg = 0;
	for(i = 0; i < N; i++) 
	{
		g[i] = polynomial[i];
		if(g[i] == -1) g[i] = 1;
		if(g[i] != 0) degg = i;
	}
	/* g[0] = -1; g[N] = 1; */
	/* first loop pass unrolled (as above g instead of f) */
	while(g[0] == 0)
	{
		PolDivX(g, N);
		degg--;
		/* c--; c(x) = 0 -> c(x) * x = 0 */ 
		k++;
	}

	/* f[0] = 1 now. f(x) == 1 not possible at this point for ntru key polynomials */
	/* deg(f) < deg(g) at this point, for g(x) = x^N - 1 */
	/* (swap f and g, b and c - see above: initalisation) */ 
	
	/* f(x) = x^N - 1 + g(x) (already swapped) */
	/* f[0] == 0 now because g[0] == 1 (while loop above) */
	/* first step of loop pass 2 in while(f[0] == 0) : */
	for(i = 0; i < N; i++)
		f[i] = mod(g[i], 2); /* f(x) += g(x) (mod 2) */
	PolDivX(f, N); /* -> f(x) += 1 -> f[0] = 0 -> f(x) /= x in first pass of step 3 + 4 */
	f[N-1] = 1; /* f(x) += x^N -> f(x) /= x in first pass of step 3 + 4 */
	degf = N - 1; /* degree of f is now obviosly == N - 1 */
	PolMulX(c,N);
	k++;
	
	/* now all polynomials are mod (x^N - 1) */
	/* step 2: */
	while(1)
	{
		/* step 3: do while f[0] = 0 */
		while(f[0] == 0)
		{
			PolDivX(f, N);
			degf--;
			PolMulX(c, N);
			k++;
		}
		/* step 5: if f(x) == 1 return */
		for(i = 1; i < N; i++)
		{
			if(f[i] != 0) break;
			if(i == N - 1) /* f(x) == 1 */
			{
				/* return is b(x) with coefficients shifted
				 * cyclically k places */
				for(i = 0; i < N; i++)
				{
					ret[i] = b[mod(i+k, N)];
				}
				free(b);
				free(f);
				free(c);
				free(g);
				return;
			}
		}
		/* step 6: if deg(f) < deg(g) */
		if(degf < degg)
		{
			/* step 7: exchange f and g and exchange b and c */
			degtmp = degf; degf = degg; degg = degtmp;
			tmp = f; f = g; g = tmp;
			tmp = b; b = c; c = tmp;
		}
		
		/* step 8 + 9: */
		for(i = 0; i < N; i++)
		{
			f[i] = mod((f[i] + g[i]), 2);
			b[i] = mod((b[i] + c[i]), 2);
		}
		if(degf < degg) degf = degg;
		else if(degf == degg) degf = degree(f, N);
	}
}

void InversePolynomialMod3(int32_t **inverse, int32_t *polynomial, int32_t N)
{
	int32_t k, i; /* counter */
	int32_t *b, *f, *c, *g, *tmp; /* polynomials */
	int32_t degf, degg, degtmp; /* degree of polynomials */
	int32_t *ret = *inverse; /* return */
	b = (int32_t *)malloc(sizeof(int32_t) * N);
	f = (int32_t *)malloc(sizeof(int32_t) * N);
	c = (int32_t *)malloc(sizeof(int32_t) * N);
	g = (int32_t *)malloc(sizeof(int32_t) * N);

	/* init */
	for(i = 0; i < N; i++)
	{
		b[i] = 0;
		f[i] = 0;
		c[i] = 0;
		g[i] = 0;
	}
	
	k = 0;
	/* c[0] = 0 */
	/* first loop pass: swap b and c (step 7 )
	 *                  b(x) = b(x) + c(x) (step 9)
	 *                  -> b(x) = c(x) = 1 
	 *                  -> no swap, init b[0] = 1 and c[0] = 1 
	 */
	c[0] = 1;
	/* first loop pass: swap f and g (step 7)
	 *                  f(x) = f(x) + g(x) (step 8)
	 *                  -> init g instead of f
	 */
	degg = 0;
	for(i = 0; i < N; i++) 
	{
		g[i] = polynomial[i];
		if(g[i] != 0) degg = i;
	}
	/* g[0] = -1; g[N] = 1; */
	/* first loop pass unrolled (as above g instead of f) */
	while(g[0] == 0)
	{
		PolDivX(g, N);
		degg--;
		/* c--; c(x) = 0 -> c(x) * x = 0 */ 
		k++;
	}

	/* f[0] = 1 now. f(x) == 1 not possible at this point for ntru key polynomials */
	/* deg(f) < deg(g) at this point, for g(x) = x^N - 1 */
	/* (swap f and g, b and c - see above: initalisation) */ 
	
	/* f(x) = x^N - 1 + g(x) (already swapped) */
	/* f[0] == 0 now because g[0] == 1 (while loop above) */
	/* first step of loop pass 2 in while(f[0] == 0) : */
	if(g[0] == -1)
	{
		for(i = 0; i < N; i++)
			f[i] = -g[i]; /* f(x) = f(x) - g(x) (mod 3) */
		b[0] = -1;
	}
	else
	{
		for(i = 0; i < N; i++)
			f[i] = g[i]; /* f(x) = f(x) - g(x) (mod 3) */
		b[0] = 1;
	}
	PolDivX(f, N); /* -> f(x) += 1 -> f[0] = 0 -> f(x) /= x in first pass of step 3 + 4 */
	f[N-1] = 1; /* f(x) += x^N -> f(x) /= x in first pass of step 3 + 4 */
	degf = N - 1; /* degree of f is now obviosly == N - 1 */
	PolMulX(c,N);
	k++;
	
	/* now all polynomials are mod (x^N - 1) */
	/* step 2: */
	while(1)
	{
		/* step 3: do while f[0] = 0 */
		while(f[0] == 0)
		{
			PolDivX(f, N);
			degf--;
			PolMulX(c, N);
			k++;
		}
		/* step 5: if f(x) == 1 return */
		for(i = 1; i < N; i++)
		{
			if(f[i] != 0) break;
			if(i == N - 1) /* f(x) == 1 */
			{
				/* return is b(x) with coefficients shifted cyclically k places */
				if(f[0] == 1)
				{
					for(i = 0; i < N; i++)
					{
						ret[i] = b[mod(i+k, N)];
					}
				}
				else /* f[0] == -1 */
				{
					for(i = 0; i < N; i++)
					{
						ret[i] = mod(-b[mod(i+k, N)],3);
					}
				}
				free(b);
				free(f);
				free(c);
				free(g);
				return;
			}
		}
		/* step 6: if deg(f) < deg(g) */
		if(degf < degg)
		{
			/* step 7: exchange f and g and exchange b and c */
			degtmp = degf; degf = degg; degg = degtmp;
			tmp = f; f = g; g = tmp;
			tmp = b; b = c; c = tmp;
		}
		
		/* step 8 + 9: */
		if(f[0] == g[0])
		{
			for(i = 0; i < N; i++)
			{
				f[i] = mod(f[i] - g[i], 3);
				b[i] = mod(b[i] - c[i], 3);
			}
		}
		else
		{
			for(i = 0; i < N; i++)
			{
				f[i] = mod((f[i] + g[i]), 3);
				b[i] = mod((b[i] + c[i]), 3);
			}
		}
		if(degf < degg) degf = degg;
		else if(degf == degg) degf = degree(f, N);
	}

}

void InversePolynomialMod_r(int32_t **inverse, int32_t *polynomial, int32_t N, int32_t prime, int32_t r)
{
	int32_t i, q, pr; /* counter, temporary integers */
	/* some temporary polynomials */
	int32_t *tmp1 = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *tmp2 = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *tmp;
	/* in the pseudo code the original polynomial os called a
	 * the returned polynomial is called b
	 * for clearer understanding */
	int32_t *b = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *a = polynomial;

	/* we have to compute the almost inverse modulo prime first
	 * and initialize the to be returned polynomial b with that almost inverse 
	 * Input: a(x), prime, r
	 *        b(x) = a(x)^(-1) mod prime */
	/* TODO: test if that really exists */
	InversePolynomialMod(&b, polynomial, N, prime);
	
	/* step 1: */
	q = prime;
	/* we also need the value of prime^r */
	pr = fastExp(prime, r);

	/* step 2: */
	while(q < pr)
	{
		/* step 3: */
		q *= q;

		/* step 4:*/
		/* tmp1(x) = a(x) * b(x) */
		cyclicConvolutionMod(tmp1, a, b, N, q);
		/* tmp1(x) = 2 - tmp1(x) */
		tmp1[0] = mod(2 - tmp1[0], q);
		for(i = 1; i < N; i++)
			tmp1[i] = -tmp1[i];
		/* tmp2(x) = b(x) * tmp1(x) = b(x)*(2 - a(x) * b(x)) */
		cyclicConvolutionMod(tmp2, b, tmp1, N, q);
		/* assign tmp2 to b */
		tmp = b;
		b = tmp2;
		tmp2 = tmp;
	}
	/* assign to to be returned polynomial */
	for(i = 0; i < N; i++)
		(*inverse)[i] = mod(b[i], pr);
	free(b);
	free(tmp1);
	free(tmp2);
	return;
}

void cyclicConvolutionMod(int32_t *prod, int32_t *pol1, int32_t *pol2, int32_t N, int32_t modulo)
{
	cyclicConvolution(prod, pol1, pol2, N);
	int32_t i;
	/* reduce mod modulo */
	for(i = 0; i < N; i++)
		prod[i] = mod(prod[i], modulo);
	return;
}


void cyclicConvolution(int32_t *prod, int32_t *pol1, int32_t *pol2, int32_t N)
{
	int32_t i, k;

	/* init with zeros */
	for(i = 0; i < N; i++)
		prod[i] = 0;
	
	/* compute cyclic convolution */
	for(i = 0; i < N; i++)
	{
		for(k = 0; k < N; k++)
		{
			prod[mod(i+k, N)] += pol1[i]*pol2[k];
		}
	}
	return;
}



void PolMulX(int32_t *polynomial, int32_t N)
{
	int32_t i, tmp;
	tmp = polynomial[N-1];
	for(i = N-2; i >= 0; i--)
		polynomial[i+1] = polynomial[i];
	polynomial[0] = tmp;
}

int32_t mod(int32_t k, int32_t N)
{
	int32_t ret = k%N;
	return ret < 0 ? ret + N : ret;
}

int32_t degree(int32_t *polynomial, int32_t N)
{
	int32_t ret;
	for(ret = N-1; ret > 0; ret--)
	{
		if(polynomial[ret] != 0) return ret;
	}
	return 0;
}

void PolDivX(int32_t *polynomial, int32_t N)
{
	int32_t i;
	for(i = 0; i < N - 1; i++)
		polynomial[i] = polynomial[i+1];
	/* polynomial[0] == 0 */
	polynomial[N-1] = 0;
}


void importMPZ(mpz_t *number, uint8_t* bin, int32_t length)
{
	/* mpz_t, word count, word order, word size, byte order,
	 * bits skipped, binary data */
	mpz_import(*number, length, 1, sizeof(uint8_t), 1, 0, (const void *)bin);
	return;
}

void exportMPZ(mpz_t *number, uint8_t **bin, int32_t *length)
{
	uint8_t *ret;
	size_t len, c;

	/* compute needed space (see gmp doc) */
	c = sizeof(uint8_t) * 8;
	len = (mpz_sizeinbase(*number, 2) + c - 1) / c;
	/* allocate sufficient memory */
	ret = malloc(len);
	/* export to binary data */
	/* binary data, written length, word order, word size, byte order,
	 * bits skipped, mpz_t */
	mpz_export(ret, &len, 1, sizeof(uint8_t), 1, 0, *number);
	(*length) = len;
	(*bin) = ret;
	return;
}

void writePrivate(uint8_t **privatekey, int32_t *length, int32_t *f, int32_t *F_p, int32_t N, int32_t p, int32_t q)
{
	uint8_t *buffer;
	int32_t bufferlen;
	uint8_t *binf, *binF_p;
	int32_t binlenf, binlenF_p;
	/* write polynomials to binary data (gmp) */
	/* allocates memory for binf, binF_p */
	polynomialToBinary(&binf, &binlenf, f, N, p);
	polynomialToBinary(&binF_p, &binlenF_p, F_p, N, p);
	/* compute length of buffer and allocate the according amount of memory
	 * writing N, p, q, binlenf, binlenF_p, binf, binF_p to buffer */
	bufferlen = 20 + binlenf + binlenF_p;
	buffer = (uint8_t*)malloc(bufferlen * sizeof(uint8_t));
	int32_t i = 0;
	writeIntToBuffer(&(buffer[i]), N);
	i += 4;
	writeIntToBuffer(&(buffer[i]), p);
	i += 4;
	writeIntToBuffer(&(buffer[i]), q);
	i += 4;
	writeIntToBuffer(&(buffer[i]), binlenf);
	i += 4;
	writeIntToBuffer(&(buffer[i]), binlenF_p);
	i += 4;
	int32_t k;
	for(k = 0; k < binlenf; k++)
		buffer[i + k] = binf[k];
	i += binlenf;
	for(k = 0; k < binlenF_p; k++)
		buffer[i + k] = binF_p[k];
	
	/* return values */
	*length = bufferlen;
	*privatekey = buffer;

	/* clean up */
	free(binf);
	free(binF_p);
	return;
}

void writePublic(uint8_t **publickey, int32_t *length, int32_t *h, int32_t N, int32_t p, int32_t q, int32_t d)
{
	/* buffer for public key h */
	uint8_t *binh;
	/* length of that buffer */
	int32_t binlenh;
	/* write polynomial h to that buffer
	 * allocates memory for binh */
	polynomialToBinary(&binh, &binlenh, h, N, q);
	
	/* compute needed length of buffer and allocate the memory 
	 * writing N, p, q, binlenh, binh to buffer */
	int32_t bufferlen = 20 + binlenh;
	uint8_t *buffer = (uint8_t*)malloc(bufferlen * sizeof(uint8_t));
	int32_t i = 0;
	writeIntToBuffer(&(buffer[i]), N);
	i += 4;
	writeIntToBuffer(&(buffer[i]), p);
	i += 4;
	writeIntToBuffer(&(buffer[i]), q);
	i += 4;
	writeIntToBuffer(&(buffer[i]), d);
	i += 4;
	writeIntToBuffer(&(buffer[i]), binlenh);
	i += 4;
	int32_t k;
	for(k = 0; k < binlenh; k ++)
		buffer[i + k] = binh[k];
	
	/* return values */
	*length = bufferlen;
	*publickey = buffer;

	/* clean up */
	free(binh);
	return;
}

void readPrivate(NTRU_Decrypt_ctx *d_ctx, uint8_t *priv)
{
	int32_t i = 0;
	d_ctx->N = readIntFromBuffer(priv);
	i += 4;
	d_ctx->p = readIntFromBuffer(&(priv[i]));
	i += 4;
	d_ctx->q = readIntFromBuffer(&(priv[i]));
	i += 4;
	int32_t binlenf = readIntFromBuffer(&(priv[i]));
	i += 4;
	int32_t binlenF_p = readIntFromBuffer(&(priv[i]));
	i += 4;
	/* read polynomial f */
	binaryToPolynomial(&(priv[i]), binlenf, &(d_ctx->f), d_ctx->N, d_ctx->p);
	i += binlenf;
	/* read polynomial F_p */
	binaryToPolynomial(&(priv[i]), binlenF_p, &(d_ctx->F_p), d_ctx->N, d_ctx->p);
	
	/* fix allignement of coefficients, so that they are in {-p/2, ..., +p/2} */
	int32_t p = d_ctx->p;
	int32_t p2 = p/2;
	for(i = 0; i < d_ctx->N; i++)
	{
		if(d_ctx->f[i] > p2)
			d_ctx->f[i] -= p;
		if(d_ctx->F_p[i] > p2)
			d_ctx->F_p[i] -= p;
	}
	return;
}

void readPublic(NTRU_Encrypt_ctx *e_ctx, uint8_t *pub)
{
	/* read N, p, q from pub */
	int32_t i = 0;
	e_ctx->N = readIntFromBuffer(pub);
	i += 4;
	e_ctx->p = readIntFromBuffer(&(pub[i]));
	i += 4;
	e_ctx->q = readIntFromBuffer(&(pub[i]));
	i += 4;
	e_ctx->d = readIntFromBuffer(&(pub[i]));
	i += 4;
	/* read length of pupblic key h from buffer */
	int32_t binlenh = readIntFromBuffer(&(pub[i]));
	i += 4;
	/* memory for public key polynomial will be allocated
	 * and read from buffer */

	binaryToPolynomial(&(pub[i]), binlenh, &(e_ctx->h), e_ctx->N, e_ctx->q);
	/* fix allignement of coefficients, so that  they are in {-q/2, ..., +q/2} */
	int32_t q = e_ctx->q;
	int32_t q2 = q/2;
	for(i = 0; i < e_ctx->N; i ++)
	{
		if(e_ctx->h[i] > q2)
			e_ctx->h[i] -= q;
	}
	return;
}

void polynomialToBinary(uint8_t **buffer, int32_t *length, int32_t *polynomial, int32_t N, int32_t base)
{
	int32_t i, temp;
	mpz_t number;
	mpz_t tmp;
	mpz_init(number);
	mpz_init(tmp);
	/* here all coefficients has to be in {0, ..., base-1}
	 * this has to be reverted in read out process */
	temp = polynomial[0];
	/* allign to {0, ..., base-1} */
	if(temp < 0) temp += base;
	mpz_set_ui(number, temp);
	for(i = 1; i < N; i++)
	{
		/* get next coeff */
		temp = polynomial[i];
		if(temp < 0) temp += base;
		mpz_set_ui(tmp, temp);
		
		/* TODO: OPTIMIZE with mpz_mul_2exp */
		/* tmp = tmp + number * base */
		mpz_addmul_ui(tmp, number, base);

		/* reassign TODO: pointers ! */
		mpz_swap(tmp, number);
	}
	
	/* number is now our mpz_t representation of polynomial */
	/* write number as binary data to buffer */
	exportMPZ(&number, buffer, length);

	mpz_clear(tmp);
	mpz_clear(number);
	return;
}

void binaryToPolynomial(uint8_t *buffer, int32_t length, int32_t **polynomial, int32_t N, int32_t base)
{
	/* TODO */
	int32_t *pol = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t i;
	mpz_t num;
	mpz_init(num);
	mpz_t *number = &num;
	importMPZ(number, buffer, length);

	mpz_t remainder;
	mpz_init(remainder);
	mpz_t quot;
	mpz_init(quot);
	mpz_t *quotient = &quot;
	mpz_t *swapmpz;
	for(i = N - 1; i >= 0; i--)
	{	/* divides number by base, returns quotient and remainder */
		mpz_fdiv_qr_ui(*quotient, remainder, *number, base);
		pol[i] = (int32_t)mpz_get_ui(remainder);
		if(pol[i] > base/2) pol[i] -= base;
		swapmpz = quotient;
		quotient = number;
		number = swapmpz;
	}
	
	mpz_clear(remainder);
	mpz_clear(*quotient);
	mpz_clear(*number);
	(*polynomial) = pol;
	return;
}


void writeIntToBuffer(uint8_t *buffer, int32_t n)
{
	/* lets hope that the buffer has at least 4 bytes */
	int32_t *buf = (int32_t*)buffer;
	*buf = n;
	return;
}

int32_t readIntFromBuffer(uint8_t *buffer)
{
	/* lets hope that the buffer has at least 4 bytes */
	int32_t *buf = (int32_t*)buffer;
	return *buf;
}



void toBase3(NTRU_Encrypt_ctx *e_ctx, int32_t **buffer3, int32_t *length3, uint8_t *buffer2, int32_t length2, uint8_t final)
{
	/* no data, no final call */
	if(length2 < 1 && !final)
	{
		*buffer3 = NULL;
		*length3 = 0;
		return;
	}

	
	/* bitmask lowest 19 bits set, to extract 19 bit integer
	 * MASK19 = 00000000.00000111.11111111.11111111
	 * most significant bit first */
	const int32_t MASK19 = 0x7FFFF;
	/* init environment with not yet processed data
	 * 0 at inital call through NTRU_Encrypt_Init */
	int32_t currentBits = e_ctx->base3_currentBits;
	int32_t work = e_ctx->base3_bits;

	uint8_t tp; /* memory location for read byte */
	int32_t bufferP = 0; /* number of current buffer2 byte */
	/* temporary memory for input/output processing */
	int32_t tmp;
	int32_t dest;

	/* initalize return buffer3 */
	int32_t *ret = NULL; /* buffer */
	int32_t retsize = 0; /* allocated memory counter */
	int32_t usage = 0; /* buffer length */

	while(1)
	{
		/* read 8 bits (1 byte) until we have at least 19 bits acquired */
		while(currentBits < 19)
		{
			/* read 8 bits, if there are still some left */
			if(bufferP >= length2)
			{
				/* no bits left to read 
				 * store remaining bits in e_ctx for further
				 * processing, cleaned up at NTRU_Encrypt_Final */
				e_ctx->base3_bits = work;
				e_ctx->base3_currentBits = currentBits;
				
				/* if final call: clean up */
				if(final)
				{
					/* laod remaining data */
					work = e_ctx->base3_bits;
					currentBits = e_ctx->base3_currentBits;
					/* count trailing zeros that are not
					 * part of original data */
					e_ctx->base3_trailing = 19 - currentBits;
					/* encode remaining data */
					encode_2_19_3_12(&ret, &retsize, &usage, work);
				}

				*length3 = usage;
				*buffer3 = ret;
				return;
			}
			/* there are still bits to read */
			tp = buffer2[bufferP];
			bufferP += 1;
			/* cast to 32bit integer */
			tmp = (int32_t) tp;
			/* add bits to work at the right position
			 * we have currentBits at the moment */
			work += (tmp << currentBits);
			/* we acquired 8 additional bits */
			currentBits += 8;
		}
		/* we have at least 19 bits
		 * encode that 19 bits to trinary data */
		/* reduce currentBits counter by 19 */
		currentBits -= 19;
		/* mask the least significant 19 bits */
		dest = work & MASK19;
		/* shift bits in work into the right position */
		work >>= 19;
		/* encode */
		encode_2_19_3_12(&ret, &retsize, &usage, dest);
	}
}

void fromBase3(NTRU_Decrypt_ctx *d_ctx, uint8_t **buffer2, int32_t *length2, int32_t *buffer3, int32_t length3, uint8_t final)
{
	/* check constraints */
	if(length3 < 1 && !final) 
	{
		*buffer2 = NULL;
		*length2 = 0;
		return;
	}
	if(length3 % 12 != 0)
	{
		*buffer2 = NULL;
		*length2 = 0;
		return;
	}

	/* init return buffer */
	uint8_t *ret = NULL;
	int32_t retsize = 0;
	int32_t usage = 0;
	/* countervaraible */
	int32_t i;
	
	/* variables for input/output processing */
	int32_t tmp;
	int32_t work = d_ctx->base3_bits;
	int32_t currentBits = d_ctx->base3_currentBits;

	/* read all 12 digit trinary numbers available */
	for(i = 0; i < length3; i += 12)
	{
		/* write out all completed bytes */
		while(currentBits >= 8)
		{
			/* allocate needed memory */
			if(usage >= retsize)
			{
				retsize += 512;
				ret = (uint8_t*)realloc(ret, retsize * sizeof(uint8_t));
			}
			/* write lsb of work to ret */
			ret[usage] = (uint8_t)(work & 0xFF);
			/* shift out the written 8 bits */
			work >>= 8;
			/* update counters accordingly */
			usage += 1;
			currentBits -= 8;
		}

		tmp = decode_2_19_3_12(&(buffer3[i]));
		/* tmp holds 19 digit binary integer */
		/* shift that 19 bits to the right position and add to work */
		tmp <<= currentBits;
		work += tmp;
		/* set counter of currentBits accordingly */
		currentBits += 19;

		/* don't write out last bytes, will be handled if final != 0
		 * or in next call */
		/*if(i == length3 - 12) break;*/

	}
	/* store still remaining bits in work in decryption context */
	d_ctx->base3_bits = work;
	d_ctx->base3_currentBits = currentBits;


	/* if final call clean up (called from NTRU_Decrypt_Final) */
	if(final)
	{
		work = d_ctx->base3_bits;
		currentBits = d_ctx->base3_currentBits;
		/* cut trailing nondata zeros */
		currentBits -= d_ctx->base3_trailing;
		/* write out remaining bytes */

		while(currentBits >= 8)
		{
			/* allocate needed memory */
			if(usage >= retsize)
			{
				retsize += 4;
				ret = (uint8_t*)realloc(ret, retsize*sizeof(uint8_t));
			}
			/* write lsb of work to ret */
			ret[usage] = (uint8_t)(work & 0xFF);
			/* shift out the written 8 bits */
			work >>= 8;
			/* update counters accordingly */
			usage += 1;
			currentBits -= 8;
		}
	}

	*length2 = usage;
	*buffer2 = ret;
	return;
}

void encode_2_19_3_12(int32_t **buf, int32_t *retsize, int32_t *usage, int32_t n)
{
	int k = 0;
	/* convert n to base 3 and store digits in *buf */
	int32_t x = n;
	int32_t rem;

	while(k < 12)
	{
		rem = (x % 3);
		x /= 3;
		/* buffer already full */
		if(*retsize <= *usage)
		{
			*retsize += 512;
			(*buf)=(int32_t*)realloc(*buf, *retsize * sizeof(int32_t));
		}
		(*buf)[*usage] = rem;
		*usage += 1;
		k += 1;
	}
	return;
}

int32_t decode_2_19_3_12(int32_t *buf)
{
	int32_t ret = 0;
	int8_t i;
	for(i = 11; i >= 0; i--)
	{
		ret *= 3;
		ret += buf[i];
	}
	return ret;
}


void NTRU_Encrypt(NTRU_Encrypt_ctx *e_ctx, NTRU_Container *con, uint8_t **encrypted, int32_t *enclength)
{
	int32_t i;
	/* extract plaintext polynomial */
	int32_t *m = con->polynomial;
	/* encrypted polynomial */
	int32_t *e = (int32_t*)malloc(e_ctx->N * sizeof(int32_t));
	/* encrypt */
	/* random polynomial */
	int32_t *r = (int32_t*)malloc(e_ctx->N * sizeof(int32_t));
	RandomTriPolynomial(&r, e_ctx->d, e_ctx->d, e_ctx->N);
	/* p * r */
	for(i = 0; i < e_ctx->N; i++)
		r[i] *= e_ctx->p;
	/* p * r * h mod q */
	cyclicConvolutionMod(e, r, e_ctx->h, e_ctx->N, e_ctx->q);
	free(r);
	/* e = p * r * h  + m mod q */
	/* TODO: DEBUG */
	/*printf("[ENCRYPT] e = \n");*/
	for(i = 0; i < e_ctx->N; i++)
	{
		e[i] = mod(e[i] + m[i], e_ctx->q);
		/* DEBUG **/
		/*printf("%d, ", e[i]);*/
	}
	/*printf("\n");*/
	/******************/

	/* convert polynomial e to binary data */
	uint8_t *buffer;
	int32_t length;
	polynomialToBinary(&buffer, &length, e, e_ctx->N, e_ctx->q);

	/*DEBUG ******/
	/*printf("[ENCRYPT] trailingCoeff: [%d]\n[ENCRYPT] trailingBits: [%d]\n",*/
			/*con->trailingZeroCoefficients, con->trailingZeroBits);*/
	/*printf("[ENCRYPT] length: [%d]\n", length);*/
	/*****************/
	/* writing con->trailingZeroCoefficients
	 *         con->trailingZeroBits
	 *         length
	 *         buffer */
	int32_t retlength = 12 + length;
	uint8_t *ret = (uint8_t*)malloc(retlength * sizeof(uint8_t));
	/* write protokoll data to buffer */
	writeIntToBuffer(&(ret[0]), con->trailingZeroCoefficients);
	writeIntToBuffer(&(ret[4]), con->trailingZeroBits);
	writeIntToBuffer(&(ret[8]), length);
	/* write encrypted polynomial to buffer */
	for(i = 0; i < length; i++)
		ret[i + 12] = buffer[i];
	free(buffer);
	/* return buffer and its length */
	*enclength = retlength;
	*encrypted = ret;
	free(e);
	return;
}

int32_t NTRU_Decrypt(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t *encrypted, int32_t enclength)
{
	/* corrupt data, shouldn't happen */
	if(enclength < 12) 
	{
		/* TODO DEBUG */
		/*printf("enclength not valid\n");*/
		return 0;
	}

	NTRU_Container *ret = con;
	ret->polynomial = (int32_t*)malloc(d_ctx->N * sizeof(int32_t));
	/* extract protocoll data */
	int32_t length;
	ret->trailingZeroCoefficients = readIntFromBuffer(&(encrypted[0]));
	ret->trailingZeroBits = readIntFromBuffer(&(encrypted[4]));
	length = readIntFromBuffer(&(encrypted[8]));

	/* DEBUG *************/
	/*printf("[DECRYPT] trailingCoefficients: [%d]\n",*/
			/*ret->trailingZeroCoefficients);*/
	/*printf("[DECRYPT] trailingBits: [%d]\n", ret->trailingZeroBits);*/
	/*printf("[DECRYPT] length: [%d]\n", length);*/
	/*********************/

	/* check for corruption enclength != length + 12 */
	if(length + 12 != enclength) 
	{
		return 0;
	}
	/* extract encrypted data, and convert to polynomial, allign */
	int32_t *e;
	binaryToPolynomial(&(encrypted[12]), length, &e, d_ctx->N, d_ctx->q);
	int32_t i;
	/* decrypt */
	/* a = f * e */
	int32_t *a = (int32_t*)malloc(d_ctx->N * sizeof(int32_t));

	cyclicConvolutionMod(a, d_ctx->f, e, d_ctx->N, d_ctx->q);

	/*printf("[DECRYPT] e = \n");*/
	/*for(i = 0; i < d_ctx->N; i++)*/
		/*printf("%d, ", e[i]);*/
	/*printf("\n");*/

	free(e);
	/* check if decryption is possible,
	 * coefficients have to be in (-q/2, ..., q/2] */
	int32_t q2 = d_ctx->q / 2;
	for(i = 0; i < d_ctx->N; i++)
		if(a[i] > q2) a[i] -= 2*q2;
	/*for(i = 0; i < d_ctx->N; i++)
	{
		if(a[i] > q2 || a[i] <= -q2)
		{
			[> if failure free memory, return 0 <]
			printf("[NTRU DECRYPT] [%d] FAIL FAIL\n", a[i]);
			free(ret->polynomial);
			free(a);
			return 0;
		}
	}*/
	/*printf("\n");*/
	/* decryption successful, retrieve plaintext m */
	/* m = F_p * a mod p */
	cyclicConvolutionMod(ret->polynomial, d_ctx->F_p, a, d_ctx->N, d_ctx->p);
	free(a);
	return 1; /* True */
}

void NTRU_Encrypt_Preprocess_Update(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count, uint8_t *plaintext, int32_t plainlength)
{
	NTRU_Encrypt_Preprocess(e_ctx, cons, count, plaintext, plainlength, 0);
	return;
}

void NTRU_Encrypt_Preprocess_Final(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count)
{
	NTRU_Encrypt_Preprocess(e_ctx, cons, count, NULL, 0, 1);
	return;
}

void NTRU_Encrypt_Preprocess(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count, uint8_t *plaintext, int32_t plainlength, int32_t final)
{
	/* if plainlength == 0 -> Final */
	/* init imemory for return values */
	int32_t containerCount = 1;
	int32_t currentContainer = 0;
	NTRU_Container *ret = (NTRU_Container *)malloc(
			containerCount * sizeof(NTRU_Container));
	ret[currentContainer].polynomial = NULL;

	/* base3 conversion */
	int32_t *buffer3 = NULL;
	int32_t length3 = 0;
	/* allocates buffer3 */
	toBase3(e_ctx, &buffer3, &length3, plaintext, plainlength, final);
	/* count read elements from buffer3 */
	int32_t curBuffer3 = 0;

	/* fill NTRU_Containers */
	/* init */
	int32_t *coeffs = e_ctx->coefficients;
	int32_t curCoeff = e_ctx->coefficientCount;
	/* fill with numbers from buffer3 until we have N */
	while(1)
	{
		/* fill coefficients */
		for(; curCoeff < e_ctx->N; curCoeff++)
		{
			/* buffer3 cleared ? */
			if(curBuffer3 == length3) break;

			/* read next number */
			coeffs[curCoeff] = buffer3[curBuffer3];
			curBuffer3++;
		}
		/* if buffer3 is cleared, keep last coefficients,
		 * even if we have read N coefficients
		 * cleaned up in NTRU_Encrypt_Preprocess_Final call
		 * prob it is needed to set trailingZeroBits */
		if(curBuffer3 == length3) break;
		/* otherwise push out another container, we have N coeffs! */
		curCoeff = 0;
		if(currentContainer == containerCount)
		{
			containerCount += 1;
			ret = (NTRU_Container *)realloc(ret,
					containerCount * sizeof(NTRU_Container));
			ret[currentContainer].polynomial = NULL;
		}
		/* set values */
		ret[currentContainer].trailingZeroCoefficients = 0;
		ret[currentContainer].trailingZeroBits = 0;
		/* move coeffs array from e_ctx to ret */
		ret[currentContainer].polynomial = coeffs;

		/* TODO: DEBUG */
		/*printf("[UPDATE]\ncurrentContainer: [%d]\npolynomial: [", currentContainer);
		for(i = 0; i < e_ctx->N; i++)
			printf("%d ", coeffs[i]);
		printf("]\n");
*/
		/* new coeffs array for e_ctx */
		coeffs = (int32_t*)malloc(e_ctx->N * sizeof(int32_t));
		currentContainer++;
	}
	/* free buffer3, no longer needed */
	if(buffer3 != NULL)
		free(buffer3);

	if(final)
	{
		if(currentContainer == containerCount)
		{
			/* we need max one more */
			containerCount++;
			ret = (NTRU_Container*)realloc(ret,
						containerCount *
						sizeof(NTRU_Container));
		}
		ret[currentContainer].trailingZeroCoefficients =
			e_ctx->N - curCoeff;
		ret[currentContainer].trailingZeroBits = e_ctx->base3_trailing;
		/* set trailing coeffs to 0 */
		for(; curCoeff < e_ctx->N; curCoeff++)
			coeffs[curCoeff] = 0;
		ret[currentContainer].polynomial = coeffs;

		/* TODO: DEBUG */
		/*printf("[FINAL]\ncurrentContainer: [%d]\n", currentContainer);*/

		e_ctx->coefficients = NULL;
		e_ctx->coefficientCount = 0;

		/* DEBUG ******************************/
		/*printf("trailingCoeffs: [%d]\n", 
				ret[currentContainer].trailingZeroCoefficients);
		[>printf("trailingBits: [%d]\n", e_ctx->base3_trailing)<]
		printf("Container: [");
		for(i = 0; i < e_ctx->N; i++)
			printf("%d ", ret[currentContainer].polynomial[i]);
		printf("]\n");*/
		/**************************************/
		currentContainer++;
	}
	else
	{
		e_ctx->coefficients = coeffs;
		e_ctx->coefficientCount = curCoeff;
	}
	*cons = ret;
	*count = currentContainer;
	return;
}

void NTRU_Decrypt_Postprocess_Update(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t **plaintext, int32_t *plainlength)
{
	NTRU_Decrypt_Postprocess(d_ctx, con, plaintext, plainlength, 0);
	return;
}

void NTRU_Decrypt_Postprocess_Final(NTRU_Decrypt_ctx *d_ctx, uint8_t **plaintext, int32_t *plainlength)
{
	NTRU_Decrypt_Postprocess(d_ctx, NULL, plaintext, plainlength, 1);
	return;
}

void NTRU_Decrypt_Postprocess(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t **plaintext, int32_t *plainlength, int32_t final)
{
	if(!final)
	{
		/* init */
		int32_t curCount = d_ctx->coefficientCount;

		/* extract information from con */
		/* read a multiple of 12 digits */
		/* how much have we? curCount + number of valid coefficients
		 * (from con), max N */
		int32_t numCoeffs = curCount + d_ctx->N -
			con->trailingZeroCoefficients; /* != 0 in last package */
		/*TODO DEBUG */
		/*printf("valid Coeffs: [%d]\n", numCoeffs);*/
		/*******************/
		/* != 0 in last package */
		d_ctx->base3_trailing = con->trailingZeroBits;

		/* should be multiple of 12, but hold at least last 12 back
		 * for we possibly need to cut trailing bits in base 3
		 * conversion */
		numCoeffs = numCoeffs - mod(numCoeffs, 12) - 12;
		if(numCoeffs < 0) numCoeffs = 0; /* no negative count */
		int32_t *coeffs = (int32_t*)malloc(numCoeffs * sizeof(int32_t));
		
		/* get remains from last call */
		int32_t i;
		for(i = 0; i < curCount; i++)
			coeffs[i] = (d_ctx->coefficients)[i];
		if(d_ctx->coefficients != NULL)
			free(d_ctx->coefficients);
		
		/* fill up with digits from con */
		int32_t k = 0;
		for(; i < numCoeffs; i++)
		{
			coeffs[i] = (con->polynomial)[k];
			k++;
		}

		/* store remainig coefficients in d_ctx->coefficients */
		d_ctx->coefficients = (int32_t*)malloc((d_ctx->N - k) *
				sizeof(int32_t));
		i = 0;
		for(; k < d_ctx->N; k++)
		{
			(d_ctx->coefficients)[i] = (con->polynomial)[k];
			i++;
		}
		d_ctx->coefficientCount = i - con->trailingZeroCoefficients;

		/* convert from base3 */
		fromBase3(d_ctx, plaintext, plainlength, coeffs, numCoeffs, 0);
		if(coeffs != NULL)
			free(coeffs);
	}
	else
	{
		/* TODO: DEBUG */
		/*printf("[FINAL]\n");*/
		/**************/
		/* DEBUG */
		if(d_ctx->coefficientCount % 12)
			fprintf(stderr, "[NTRU DECRYPT] FAIL: package loss\n");

		/* convert ramaining digits */
		fromBase3(d_ctx, plaintext, plainlength, d_ctx->coefficients,
				d_ctx->coefficientCount, 1);
	}

	return;
}
