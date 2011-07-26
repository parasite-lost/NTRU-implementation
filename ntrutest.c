#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "ntrutest.h"




void printPolynomial(int32_t *pol, int32_t N)
{
	if(pol == NULL)
		printf("\nNULL\n");
	int32_t i;
	printf("\n     ");
	for(i = 0; i < N; i++)
	{
		printf("%d, ", pol[i]);
		if(i%20 == 19)
			printf("\n     ");
	}
	printf("\n");
	return;
}

void printMPZ(mpz_t *number)
{
	mpz_out_str(stdout, 10, *number);
	return;
}

int32_t countCoeff(int32_t *pol, int32_t coeff, int32_t N)
{
	int32_t i, count = 0;
	for(i = 0; i < N; i++)
	{
		if(pol[i] == coeff) count ++;
	}
	return count;
}

void check(int32_t flag)
{
	if(flag) printf("[OK]\n");
	else printf("[XX]\n");
}

int32_t equals(int32_t *pol1, int32_t *pol2, int32_t N)
{
	int32_t i;
	for(i = 0; i < N; i++)
	{
		if(pol1[i] != pol2[i]) return 0;
	}
	return 1;
}

int32_t isOne(int32_t *pol, int32_t N)
{
	int32_t i;
	if(pol[0] != 1) return 0;
	for(i = 1; i < N; i++)
	{
		if(pol[i] != 0) return 0;
	}
	return 1;
}

int32_t testBase3()
{
	/* the to be converted data */
	uint8_t *buffer2 = (uint8_t*)"asaskdfjhalsdfjhasldfkjhasldfkjhasldfkjhasd";
	int32_t length2 = strlen((char*)buffer2) + 1;

	/* setup pseudo decryption and encryption contexts */
	NTRU_Encrypt_ctx e_ctx;
	e_ctx.base3_bits = 0;
	e_ctx.base3_currentBits = 0;
	NTRU_Decrypt_ctx d_ctx;
	d_ctx.base3_bits = 0;
	d_ctx.base3_currentBits = 0;

	/* trinary data */
	int32_t *buffer3;
	int32_t length3;

	toBase3(&e_ctx, &buffer3, &length3, buffer2, length2, 1);

	int32_t trail = e_ctx.base3_trailing;

	uint8_t *buffer22;
	int32_t length22;
	d_ctx.base3_trailing = trail;
	fromBase3(&d_ctx, &buffer22, &length22, buffer3, length3, 1);
	
	uint32_t ret = !strcmp((char*)buffer2, (char*)buffer22);

	free(buffer3);
	free(buffer22);
	return ret;
}

int32_t testBase3Repeated()
{
	uint8_t *buffer21 = (uint8_t*)"askljahsdflasjdfhlasdfkhjalsdfhj";
	uint8_t *buffer22 = NULL;
	uint32_t length21, length22;
	length21 = strlen((char*)buffer21) + 1;
	length22 = 0;
	
	/* setup pseudo decryption and encryption contexts */
	NTRU_Encrypt_ctx e_ctx;
	e_ctx.base3_bits = 0;
	e_ctx.base3_currentBits = 0;
	NTRU_Decrypt_ctx d_ctx;
	d_ctx.base3_bits = 0;
	d_ctx.base3_currentBits = 0;

	/* trinary data */
	int32_t *buffer31, *buffer32;
	int32_t length31, length32;
	
	toBase3(&e_ctx, &buffer31, &length31, buffer21, length21, 0);
	toBase3(&e_ctx, &buffer32, &length32, buffer22, length22, 1);

	uint8_t *buffer23, *buffer24;
	int32_t length23, length24;
	d_ctx.base3_trailing = e_ctx.base3_trailing;

	fromBase3(&d_ctx, &buffer23, &length23, buffer31, length31, 0);
	fromBase3(&d_ctx, &buffer24, &length24, buffer32, length32, 1);
	

	uint8_t *concat1 = malloc(sizeof(uint8_t) * (length21 + length22 + 1));
	uint8_t *concat2 = malloc(sizeof(uint8_t) * (length23 + length24));



	int32_t i, k;

	for(i = 0; i < length21; i++)
		concat1[i] = buffer21[i];
	for(k = 0; k < length22; k++)
	{
		concat1[i] = buffer22[k];
		i++;
	}

	for(i = 0; i < length23; i++)
		concat2[i] = buffer23[i];
	for(k = 0; k < length24; k++)
	{
		concat2[i] = buffer24[k];
		i++;
	}

	int32_t ret = !strcmp((char*)concat1, (char*)concat2);


	free(concat1);
	free(concat2);
	free(buffer23);
	free(buffer24);
	free(buffer31);
	free(buffer32);

	return ret;
}

int testRandomPol(int32_t N)
{
	int32_t flag = 1;
	int32_t *pol = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t d1, d2;

	for(d1 = 216; d1 < 217; d1++)
	{
		for(d2 = 215; d2 < 216; d2++)
		{
			RandomTriPolynomial(&pol, d1, d2, N);
			if(countCoeff(pol, 1, N) != d1) flag = 0;
			if(countCoeff(pol, -1, N) != d2) flag = 0;
		}
	}
	
	free(pol);

	return flag;
}

int32_t testInverseCyclic(int32_t N, int32_t p, int32_t d1)
{
	int32_t *pol = malloc(N * sizeof(int32_t));
	int32_t *pol2 = malloc(N * sizeof(int32_t));
	int32_t *pol3 = malloc(N * sizeof(int32_t));
	int32_t i;
	int32_t flag = 1;
	for(i = 0; i < 20; i++)
	{
		RandomTriPolynomial(&pol, d1, d1-1, N);
		InversePolynomialMod(&pol2, pol, N, p);
		cyclicConvolutionMod(pol3, pol, pol2, N, p);
		if(!isOne(pol3, N)) flag = 0;
	}
	
	free(pol);
	free(pol2);
	free(pol3);

	return flag;
}
int32_t testInverseR(int32_t N, int32_t d1, int32_t q0)
{
	int32_t flag = 1;
	
	int32_t *pol = malloc(N * sizeof(int32_t));
	int32_t *pol2 = malloc(N * sizeof(int32_t));
	int32_t *pol3 = malloc(N * sizeof(int32_t));
	int32_t r, i;

	for(r = 2; r < 4; r++)
	{
		for(i = 0; i < 10; i++)
		{
			RandomTriPolynomial(&pol, d1, d1-1, N);
			InversePolynomialMod_r(&pol2, pol, N, q0, r);
			cyclicConvolutionMod(pol3, pol, pol2, N, fastExp(q0, r));
			if(!isOne(pol3, N)) flag = 0;
		}
	}

	free(pol);
	free(pol2);
	free(pol3);

	return flag;
}


int32_t testBinaryConversion(int32_t N, int32_t p, int32_t d1)
{
	int32_t flag = 1, i;
	uint8_t *buffer;
	int32_t bufferlength;
	
	int32_t *pol = malloc(N * sizeof(int32_t));
	int32_t *pol4;
	
	/* base = p */
	for(i = 0; i < 20; i++)
	{
		RandomTriPolynomial(&pol, d1, d1-1, N);
		polynomialToBinary(&buffer, &bufferlength, pol, N, p);
		binaryToPolynomial(buffer, bufferlength, &pol4, N, p);
		if(!equals(pol, pol4, N)) flag = 0;
		/* buffer and pol4 allocated */
		free(buffer);
		free(pol4);
	}
	/* base = q0^r */
	
	free(pol);

	return flag;
}

int32_t testPrePostproc()
{
	NTRU_Encrypt_ctx e_ctx;
	NTRU_Decrypt_ctx d_ctx;
	uint8_t *priv, *pub;
	int32_t privlen, publen;
	NTRU_GenKeys_HighSec(&priv, &privlen, &pub, &publen);
	NTRU_Encrypt_Init(&e_ctx, pub);
	NTRU_Decrypt_Init(&d_ctx, priv);
	free(priv);
	free(pub);

	uint8_t *input = (uint8_t*)"A";
	int32_t ilen = 1 + strlen((char*)input);
	NTRU_Container *con1 = NULL;
	NTRU_Container *con2 = NULL;
	int32_t countcon1 = 0;
	int32_t countcon2 = 0;
	NTRU_Encrypt_Preprocess_Update(&e_ctx, &con1, &countcon1, input, ilen);
	NTRU_Encrypt_Preprocess_Final(&e_ctx, &con2, &countcon2);

	uint8_t *out = malloc(1000 * sizeof(uint8_t));

	int32_t l = 0, i = 0, k = 0;
	uint8_t *plain = NULL;
	int32_t plainlen = 0;
	for(; l < countcon1; l++)
	{
		NTRU_Decrypt_Postprocess_Update(&d_ctx, &con1[l], &plain, &plainlen);
		for(i = 0; i < plainlen; i++)
		{
			out[k] = plain[i];
			k++;
		}
	}
	for(l = 0; l < countcon2; l++)
	{
		NTRU_Decrypt_Postprocess_Update(&d_ctx, &con2[l], &plain, &plainlen);
		for(i = 0; i < plainlen; i++)
		{
			out[k] = plain[i];
			k++;
		}
	}
	NTRU_Decrypt_Postprocess_Final(&d_ctx, &plain, &plainlen);
	for(i = 0; i < plainlen; i++)
	{
		out[k] = plain[i];
		k++;
	}
	int32_t flag = 0;
	
	if(!strcmp((char*)input, (char*)out)) flag = 1;


	freeContainer(con1, countcon1);
	freeContainer(con2, countcon2);
	freeEncrypt_ctx(&e_ctx);
	freeDecrypt_ctx(&d_ctx);
	free(plain);
	free(out);

	return flag;

}


int32_t testWritePriv(int32_t N, int32_t p, int32_t q0, int32_t r, int32_t df, int32_t dg, int32_t d)
{
	int32_t q = fastExp(q0, r);
	int32_t *f = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *h = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *g = (int32_t*)malloc(N * sizeof(int32_t));
	/* almost inverse polynomials of f */
	int32_t *Fp = (int32_t*)malloc(N * sizeof(int32_t));
	int32_t *Fq = (int32_t*)malloc(N * sizeof(int32_t));
	/* random polynomial f with d_f coefficients = 1, d_f coeffitients = -1, remaining = 0 
	 * random polynomial g with d_g coefficients = 1 and = -1, remaining = 0 */
	RandomTriPolynomial(&f, df, df - 1, N);
	RandomTriPolynomial(&g, dg, dg, N);
	/* compute the inverse modulo p, second part of private key 
	 * TODO: test if this really exists ? */
	InversePolynomialMod(&Fp, f, N, p);
	/* compute the inverse modulo q = q0^r */
	InversePolynomialMod_r(&Fq, f, N, q0, r);
	/* compute public key h = F_q * g */
	cyclicConvolutionMod(h, Fq, g, N, q);

	uint8_t *priv, *pub;
	int32_t privlength, publength;

	int32_t k = mod(N,12);

	/* write private and public key */
	writePrivate(&priv, &privlength, f, Fp, N, p, q, k);
	writePublic(&pub, &publength, h, N, p, q, d, k);

	int32_t flag = 1;
	
	NTRU_Decrypt_ctx d_ctx;
	d_ctx.f = NULL;
	d_ctx.F_p = NULL;
	d_ctx.coefficients = NULL;

	NTRU_Encrypt_ctx e_ctx;
	e_ctx.h = NULL;
	e_ctx.coefficients = NULL;

	readPrivate(&d_ctx, priv);
	readPublic(&e_ctx, pub);


	int32_t i;
	for(i = 0; i < N; i++)
		if(Fp[i] == 2) Fp[i] = -1;
	for(i = 0; i < N; i++)
		if(h[i] > q/2) h[i] -= q;

	if(!equals(d_ctx.F_p, Fp, N)) flag = 0;
	if(!equals(d_ctx.f, f, N)) flag = 0;

	if(!equals(e_ctx.h, h, N)) flag = 0;

	
	/* TODO: fix length */
	/* clean up */
	free(f);
	free(h);
	free(g);
	free(Fp);
	free(Fq);
	free(priv);
	free(pub);
	freeDecrypt_ctx(&d_ctx);
	freeEncrypt_ctx(&e_ctx);
	return flag;
}


int32_t testNTRU(int32_t N, int32_t p, int32_t q0, int32_t r, int32_t df, int32_t dg, int32_t d)
{
	NTRU_Encrypt_ctx e_ctx;
	NTRU_Decrypt_ctx d_ctx;

	uint8_t *priv, *pub;
	int32_t prl, pul;
	NTRU_GenKeys_HighSec(&priv, &prl, &pub, &pul);

	NTRU_Encrypt_Init(&e_ctx, pub);
	NTRU_Decrypt_Init(&d_ctx, priv);
	free(priv);
	free(pub);


	int32_t *m = (int32_t*)malloc(N * sizeof(int32_t));
	RandomTriPolynomial(&m, 0, 0, N);

	NTRU_Container c1;
	c1.trailingZeroCoefficients = 0;
	c1.trailingZeroBits = 0;
	c1.polynomial = m;
	NTRU_Container c2;
	c2.polynomial  = NULL;

	uint8_t *encrypted = NULL; int32_t enclength;

	int32_t success = 0;
	while(!success)
	{
		free(encrypted);
		NTRU_Encrypt(&e_ctx, &c1, &encrypted, &enclength);
		success = NTRU_Decrypt(&d_ctx, &c2, encrypted, enclength);
	}
	int32_t flag = 1;
	if(!equals(c1.polynomial, c2.polynomial, N)) flag = 0;
	if(c1.trailingZeroCoefficients != c2.trailingZeroCoefficients) flag = 0;
	if(c1.trailingZeroBits != c2.trailingZeroBits) flag = 0;

	freeEncrypt_ctx(&e_ctx);
	freeDecrypt_ctx(&d_ctx);
	free(c1.polynomial);
	free(c2.polynomial);
	free(encrypted);



	return flag;
}



int32_t testlowlevel()
{
	printf("*************************************************************\n");
	printf("*                TESTING LOW LEVEL FUNCTIONS                *\n");
	printf("*************************************************************\n");
	int32_t N = 503, p = 3, q0 = 2, r = 8, df = 216, d = 55, dg = 72;

	/*                                                              X 66 */
	printf("RandomTriPolynomial: ................................... ");
	
	check(testRandomPol(N));
	
	printf("InversePolynomialMod, cyclicConvolution: ............... ");
	
	check(testInverseCyclic(N, p, df));

	printf("InversePolynomialMod_r: ................................ ");
	check(testInverseR(N, df, q0));

	printf("Polynomial <-> binary conversion: ...................... ");

	check(testBinaryConversion(N, p, df));

	printf("Base3 conversion: ...................................... ");
	check(testBase3());

	printf("Base3 repeated conversion .............................. ");
	check(testBase3Repeated());

	printf("Test write/read key .................................... ");
	check(testWritePriv(N, p, q0, r, df, dg, d));

	printf("Pre-/Postprocessing .................................... ");
	check(testPrePostproc());

	printf("NTRU algorithm ......................................... ");
	check(testNTRU(N, p, q0, r, df, dg, d));
	
	return 0;
}

int32_t testntru()
{
	printf("*************************************************************\n");
	printf("*                  TESTING NTRU ENCRYPTION                  *\n");
	printf("*************************************************************\n");


	uint8_t *input = (uint8_t*)"AA BB CC DD EE aölfkjasdföakjsdfhlasdhjflasfjdhalsfhjdasldfhkjalsdfjhasldfkjhasldfkjhasldfkjhasdflkjhaasdfasdlkjdfsakljhfdkjhfsdkhjhjkkjhllllllllllllllllllllasdfhlkjashdflajsdhflkasdjfhalsdfhjasldfjhasldfkjhasdlfkjhasdflkjahsdlfkjhasdflkahdsfaldhfjasldfhjasldfhjkasldfkjhasdlfkjhasdflkahsdflahfjsdaldfhsjalsdfjhasldfkjhasdlfjkhasldfjkhasldfkjhasdlfkjhasdlfkajhsdlfkahsdjflahjsdfasldfhjasldfkhjasdlfkjhasdlfkjhasdlfkjhasdflkjahsdflkahsdfalsfdhjalsdfhjasdlfhkjasdlfhkjsdfasdfkjahsdfgkashdfgakshfdjgakhfsdgaksdhfgaksdhfjgaskdfhjgasdfiuzweriowuerlsdkflkasdhfglkasghlkjhsjhXXX";

	printf("%s\n", (char*)input);
	
	int32_t bytes = strlen((char*)input) + 1;

	int32_t b1;
	b1 = bytes / 3;


	uint8_t *privatekey, *publickey;
	int32_t privlength, publength;
	NTRU_GenKeys_HighSec(&privatekey, &privlength, &publickey, &publength);
	NTRU_Encrypt_ctx e_ctx;
	NTRU_Encrypt_Init(&e_ctx, publickey);
	NTRU_Decrypt_ctx d_ctx;
	NTRU_Decrypt_Init(&d_ctx, privatekey);
	free(privatekey);
	free(publickey);


	NTRU_Container *cont1 = NULL;
	int32_t lencont1 = 0;
	NTRU_Encrypt_Preprocess_Update(&e_ctx, &cont1, &lencont1, input, bytes);
	NTRU_Container *cont2 = NULL;
	int32_t lencont2 = 0;
	NTRU_Encrypt_Preprocess_Final(&e_ctx, &cont2, &lencont2);


	int32_t i;
	/*printf("f =\n");
	printPolynomial(d_ctx.f, d_ctx.N);
*/
	int32_t success;
	uint8_t *encrypted = NULL;
	int32_t enclength;
	NTRU_Container *cont3 = (NTRU_Container*)malloc(lencont1 * 
			sizeof(NTRU_Container));
	for(i = 0; i < lencont1; i++)
		cont3[i].polynomial = NULL;
	uint8_t **plain1 = (uint8_t**)malloc((lencont1) * sizeof(void*));
	int32_t *plainlen1 = (int32_t*)malloc((lencont1) * sizeof(int32_t));

	for(i = 0; i < lencont1; i++)
	{
		success = 0;
		while(!success)
		{
			if(encrypted != NULL)
				free(encrypted);
			NTRU_Encrypt(&e_ctx, &cont1[i], &encrypted, &enclength);
			success = NTRU_Decrypt(&d_ctx, &cont3[i],
					encrypted, enclength);
			if(!success)
				printf("[NTRU DECRYPT] Decryption Failure\n");
		}
		NTRU_Decrypt_Postprocess_Update(&d_ctx, &cont3[i],
				&plain1[i], &plainlen1[i]);
	}

	NTRU_Container *cont4 = (NTRU_Container*)malloc(lencont2 *
			sizeof(NTRU_Container));
	for(i = 0; i < lencont2; i++)
		cont4[i].polynomial = NULL;
	/* Final returns a additional uint8_t * */
	uint8_t **plain2 = (uint8_t**)malloc((lencont2 + 1) * sizeof(void*));
	int32_t *plainlen2 = (int32_t*)malloc((lencont2 + 1) * sizeof(void*));

	for(i = 0; i < lencont2; i++)
	{
		success = 0;
		while(!success)
		{
			if(encrypted != NULL)
				free(encrypted);
			NTRU_Encrypt(&e_ctx, &cont2[i], &encrypted, &enclength);
			success = NTRU_Decrypt(&d_ctx, &cont4[i],
					encrypted, enclength);
			if(!success)
				printf("[NTRU DECRYPT] Decryption Failure\n");
		}
		NTRU_Decrypt_Postprocess_Update(&d_ctx, &cont4[i],
				&plain2[i], &plainlen2[i]);
	}
	uint8_t *plain3;
	int32_t plainlen3;
	NTRU_Decrypt_Postprocess_Final(&d_ctx, &plain3, &plainlen3);


	/* print all in plain1 */
	int32_t k;
	for(i = 0; i < lencont1; i++)
	{
		for(k = 0; k < plainlen1[i]; k++)
			putchar((int)plain1[i][k]);
		free(plain1[i]);
	}
	for(i = 0; i < lencont2; i++)
	{
		for(k = 0; k < plainlen2[i]; k++)
			putchar((int)plain2[i][k]);
		free(plain2[i]);
	}
	for(i = 0; i < plainlen3; i++)
		putchar((int)plain3[i]);

	printf("\n");
	free(plain3);
	free(plain1);
	free(plain2);
	free(plainlen1);
	free(plainlen2);
	freeContainer(cont1, lencont1);
	freeContainer(cont2, lencont2);
	freeContainer(cont3, lencont1);
	freeContainer(cont4, lencont2);

	freeEncrypt_ctx(&e_ctx);
	freeDecrypt_ctx(&d_ctx);


	return 0;
}
