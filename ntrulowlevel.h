/***********************************************************************
 * NTRU cryptosystem implementation by Ulrich Dorsch (bachelor thesis)
 ***********************************************************************
 * header for lowlevel functions needed for encryption and decryption
 * include this header into main program for testing this functions
 ***********************************************************************
 * DOCUMENTATION:
 * TODO:
 */

#ifndef NTRU_LOWLEVEL

#include <gmp.h>
#include <stdint.h>


/* generate a random polynomial with coefficients in {-1, 0, 1}
 * *polynomial: random polynomial (sufficient memory already allocated)
 * d1: number of coefficients = 1
 * d2: numer of coefficients = -1
 * N: max degree bound
 */
void RandomTriPolynomial(int32_t **polynomial, int32_t d1, int32_t d2, int32_t N);

/* compute the almost inverse of a polynomial in Z[x]/(x^N - 1) modulo a prime
 * *inverse: almost inverse polynomial (sufficient memory already allocated)
 * polynomial: original polynom
 * N: max degree bound
 * prime: prime (almost inverse computed modulo prime)
 */
void InversePolynomialMod(int32_t **inverse, int32_t *polynomial, int32_t N, int32_t prime);
/* same as above but prime = 2, faster code */
void InversePolynomialMod2(int32_t **inverse, int32_t *polynomial, int32_t N);
/* same as above but prime = 3, faster code */
void InversePolynomialMod3(int32_t **inverse, int32_t *polynomial, int32_t N);

/* compute the almost inverse polynomial in Z[x]/(x^N - 1) modulo a prime power
 * *inverse: almost inverse polynomial modulo q0^r (sufficient memory already allocated)
 * polynom: original polynomial
 * prime: prime (almost inverse computed modulo prime^r)
 * r: prime exponent
 */
void InversePolynomialMod_r(int32_t **inverse, int32_t *polynomial, int32_t N, int32_t prime, int32_t r);

/* compute product of two polynomials in Z[x]/(x^N - 1) i.e. cyclic convolution
 * out prod: product of pol1 and pol2 (sufficient memory should be there!)
 * in pol1, pol2: original polynomials
 * in N: max degree bound
 * (in modulo: coefficients are computed modulo this number)
 */
void cyclicConvolutionMod(int32_t *prod, int32_t *pol1, int32_t *pol2, int32_t N, int32_t modulo);
void cyclicConvolution(int32_t *prod, int32_t *pol1, int32_t *pol2, int32_t N);

/* PolMulX: polynomial p(x) *= x
 */
void PolMulX(int32_t *polynomial, int32_t N);

/* compute degree of polynomial
 * polynomial: polynomial
 * N: max degree bound
 */
int32_t degree(int32_t *polynomial, int32_t N);

/* write keys to buffer
 * N, p, q: global parameters
 * d: encryption specific parameter
 * *privatekey: buffer for private key, will be allocated
 * privlength: length of above buffer
 * *publickey: buffer for public key, will be allocated
 * publength: length of above buffer
 * f, F_q: private key polynomials
 * h: public key polynomial
 */
void writePrivate(uint8_t **privatekey, int32_t *privlength, int32_t *f, int32_t *F_q, int32_t N, int32_t p, int32_t q, int32_t k);
void writePublic(uint8_t **publickey, int32_t *publength, int32_t *h, int32_t N, int32_t p, int32_t q, int32_t d, int32_t k);

/* inverse functions to the both above ones
 * d_ctx, e_ctx: decryption context and encryption context that will
 *               be setup with the data in priv and pub
 * priv: private key in binary format
 * pub: public key in binary format
 */
void readPrivate(NTRU_Decrypt_ctx *d_ctx, uint8_t *priv);
void readPublic(NTRU_Encrypt_ctx *e_ctx, uint8_t *pub);

/* write polynomial (array of coefficients modulo base) to binary data
 * *buffer: data is writte to this buffer (will be allocated)
 * length: written bytes
 * polynomial: polynomial which will be written to buffer
 * N: max degree bound of polynomial
 * base: coefficients should be considered modulo base
 */
void polynomialToBinary(uint8_t **buffer, int32_t *length, int32_t *polynomial, int32_t N, int32_t base);

/* get polynomial from binary data (recovering from above function
 * buffer: binary data that will be converted to a polynomial
 * length: bytes of binary data
 * *polynomial: memorylocation for the generated polynomial (will be allocated)
 * N: max degree bound
 * base: coefficient modulus
 */
void binaryToPolynomial(uint8_t *buffer, int32_t length, int32_t **polynomial, int32_t N, int32_t base);

/* import raw binary data as big integer
 * number: returned big integer
 * bin: raw binary data
 * length: number of bytes
 */
void importMPZ(mpz_t *number, uint8_t *bin, int32_t length);

/* export big integer as raw binary data
 * number: big integer
 * *bin: buffer for raw binary data
 * length: number of written bytes
 */
void exportMPZ(mpz_t *number, uint8_t **bin, int32_t *length);

/* fast exponentation b^e */
int32_t fastExp(int32_t b, int32_t e);

/* write an integer to a buffer as binary data
 * buffer: memory location where to place the integer
 * n: the integer to write
 */
void writeIntToBuffer(uint8_t *buffer, int32_t n);

/* recover an integer from a buffer, inverse function to the above one
 * buffer: buffer from which to read the integer
 * return: returns the integer
 */
int32_t readIntFromBuffer(uint8_t *buffer);

/* encode a 19 digit binary number to a 12 digit trinary number
 * in out buf: trinary digits (memory will be reallocated, first call with NULL)
 * in out retsize: amount of memory allocated (needed for repeated calls) 
 *                 (first call with 0)
 * in out usage: number of stored trinary digits (first call with 0)
 * n: 19 digit binary number
 */
void encode_2_19_3_12(int32_t **buf, int32_t *retsize, int32_t *usage, int32_t n);

/* decode a 19 digit binary number from a 12 digit trinary number
 * in buf: 12 trinary digits
 * return: 19 digit binary number
 */
int32_t decode_2_19_3_12(int32_t *buf);

/* converts binary data of arbitrary length to trinary data
 * in out e_ctx: encryption context
 * out buffer3: trinary data (memory will be allocated)
 * out length3: length of buffer3
 * in buffer2: binary data (bytes)
 * in length2: length of buffer2
 * in final: if final != 0 then clean up the reamaining data in e_ctx
 */
void toBase3(NTRU_Encrypt_ctx *e_ctx, int32_t **buffer3, int32_t *length3, uint8_t *buffer2, int32_t length2, uint8_t final);

/* converts trinary data of arbitrary length to binary data
 * in out d_ctx: decryption context
 * out buffer2: binary data
 * out length2: length of buffer2
 * in buffer3: trinary data
 * in length3: length of buffer3
 * in final: if final != 0 then clean up remaining data in d_ctx
 */
void fromBase3(NTRU_Decrypt_ctx *d_ctx, uint8_t **buffer2, int32_t *length2, int32_t *buffer3, int32_t length3, uint8_t final);


/* encrypt a polynomial with ntru algorithm
 * in e_ctx: encryption context
 * out encrypted: encrypted data
 * out enclength: length of encrypted data
 * in con: struct that contains plain data in form of a polynomial + 
 *         protokoll data
 */
void NTRU_Encrypt(NTRU_Encrypt_ctx *e_ctx, NTRU_Container *con, uint8_t **encrypted, int32_t *enclength);

/* decrypt a polynomial with ntru algorithm
 * in d_ctx: decryption context
 * out con: 1 struct that contains a polynomial + protokoll data
 * in encrypted: block of encrypted data, generated by NTRU_Encrypt
 * in enclength: length of that encrypted data
 * return: 0 for decryption failure, 1 for success
 */
int32_t NTRU_Decrypt(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t *encrypted, int32_t enclength);

/* generic function to process binary data, converting that data
 * to polynomials with degree bound N, coefficients to base p = 3
 * in out e_ctx: encryption context
 * out cons: structs containing the polynomials
 * out count: number of returned structs
 * in plaintext: input binary data
 * in plainlength: length of that binary data
 * in final: 0 or 1 to specify if this is the final call which will clean up
 *           the encryption context
 */
void NTRU_Encrypt_Preprocess(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count, uint8_t *plaintext, int32_t plainlength, int32_t final);

/* generic function to convert NTRU_Container, i.e. polynomials of degree bound N
 * and coefficients to base p = 3 to binary data
 * in out d_ctx: decryption context
 * in con: struct that contains the polynomial + protokoll data
 * out plaintext: returned binary data
 * out plainlength: length of the binary data
 */
void NTRU_Decrypt_Postprocess(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t **plaintext, int32_t *plainlength, int32_t final);

#define NTRU_LOWLEVEL
#endif
