/***********************************************************************
 * NTRU cryptosystem implementation by Ulrich Dorsch (bachelor thesis)
 ***********************************************************************
 * NTRU cryptographic high level functions
 * include this header for using the NTRU cryptographic functions to 
 * encrypt and decrypt data
 ***********************************************************************
 * DOCUMENTATION:
 * TODO:
 */

#ifndef NTRU_H
#include <stdint.h>

/* contains a polynomial that can be encrypted, or is result of decryption
 * contains additional protokoll information
 * only for use with the corresponding context for correct parameters */
typedef struct{
	/* number of coefficients, which aren't part of the original data */
	int32_t trailingZeroCoefficients;
	/* number of bytes, which aren't part of the orignal data */
	int32_t trailingZeroBits;
	/* NTRU polynomial */
	int32_t *polynomial;
} NTRU_Container;

/* encryption context for one encryption cycle with one keypair */
typedef struct{
	int32_t N; /* max degree bound for polynomials */
	int32_t p; /* small modul */
	int32_t q; /* big modul */
	int32_t d; /* parameter for random polynomial */
	int32_t *h; /* public key h */
	/* current number of bits that aren't yet processed */
	int32_t base3_currentBits;
	/* current not yet processed bits */
	int32_t base3_bits;
	/* trailing bits that aren't part of the original data */
	int32_t base3_trailing;
	/* coefficients of a NTRU polynomial that aren't yet packed in a
	 * NTRU_Container */
	int32_t *coefficients;
	/* number of coefficients in the coefficients buffer */
	int32_t coefficientCount;
} NTRU_Encrypt_ctx;

/* decryption context for one ddecryption cycle with one keypair */
typedef struct{
	int32_t N; /* max degree bound for polynomials */
	int32_t p; /* small modul */
	int32_t q; /* big modul */
	int32_t *f; /* private key f */
	int32_t *F_p; /* almost inverse of f modulo p */
	/* current number of bits that aren't yet processed */
	int32_t base3_bits;
	/* current not yet processed bits */
	int32_t base3_currentBits;
	/* trailing bits that aren't part of the original data */
	int32_t base3_trailing;
	/* coefficients of a NTRU polynomial that aren't yet packed in a
	 * NTRU_Container */
	int32_t *coefficients;
	/* number of coefficients in the coefficients buffer */
	int32_t coefficientCount;
} NTRU_Decrypt_ctx;

/* Generate keypair
 * out privatekey: buffer for storing the private key data in binary format
 *              (memory will be allocated)
 * out privlength: length of buffer for private key
 * out publickey: buffer for storing the private key data in binary format
 *             (memory will be allocated)
 * out publength: length of buffer for public key
 * in N: max degree bound of polynomials in (we are in Z[x]/(x^N - 1))
 * in p: small modulus (prime)
 * in q0: prime, q = q0^r is big modulus (q and p should be coprime)
 * in r: exponent of q0 -> q = q0^r
 * in d_f: parameter for private key (determines number of 1 and -1 in private key)
 * in d_g: parameter for part of public key (determines number of 1 and -1)
 * in d: parameter for random polynomial in the encryption process,
 *    (determines number of 1 and -1)
 */
void NTRU_GenKeys(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength, int32_t N, int32_t p, int32_t q0, int32_t r, int32_t d_f, int32_t d_g, int32_t d);

/* generate keys with recommended sets of parameters, calls above function
 * with preset parameters */
/* high security level:
 * N = 503
 * p = 3
 * q = 256, q0 = 2, r = 8
 * d_f = 216
 * d_g = 72
 * d = 55
 */
void NTRU_GenKeys_HighSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength);

/* medium security level:
 * N = 167
 * p = 3
 * q = 128, q0 = 2, r = 7
 * d_f = 61
 * d_g = 20
 * d = 18
 */
void NTRU_GenKeys_MediumSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength);

/* low security level:
 * N = 107
 * p = 3
 * q = 64, q0 = 2, r = 6
 * d_f = 15
 * d_g = 12
 * d = 5
*/
void NTRU_GenKeys_LowSec(uint8_t **privatekey, int32_t *privlength, uint8_t **publickey, int32_t *publength);

/* Initialize NTRU Context
 * init parameters and public key
 * in out e_ctx: NTRU context for encryption
 * in publickey: public key in binary format (returned by NTRU_GenKeys)
 */
void NTRU_Encrypt_Init(NTRU_Encrypt_ctx *e_ctx, uint8_t *publickey);

/* Update NTRU Context with chunks of plaintext message to be encrypted
 * in out e_ctx: encryption context (contains key and parameters)
 * out cons: contains processed plaintext (polynomials) ready to be encrypted
 *           directly with the NTRU algorithm
 * out count: number of polynomials
 * in plaintext: raw binary data to be prepared for encryption
 * in plainlength: number of bytes in plaintext
 */
void NTRU_Encrypt_Preprocess_Update(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count, uint8_t *plaintext, int32_t plainlength);

/* Finalize NTRU preprocessing data
 * in out e_ctx: encryption context (key and parameters)
 * out cons: contains preprocessed plaintext, ready for encryption
 * out count: number of polynomials
 * TODO: call toBase3 with final = 1
 */
void NTRU_Encrypt_Preprocess_Final(NTRU_Encrypt_ctx *e_ctx, NTRU_Container **cons, int32_t *count);

/* encrypts a NTRU_Container received from NTRU_Encrypt_Preprocess_Update / _Final
 * you have to do that in the same order you get the data from above functions
 * in out: e_ctx: encryption context
 * in con: contains a single polynomial (received from above functions)
 * out encrypted: encrypted binary data, ready to send to receiver
 * out enclength: length of encrypted binary data
 */
void NTRU_Encrypt(NTRU_Encrypt_ctx *e_ctx, NTRU_Container *con, uint8_t **encrypted, int32_t *enclength);

/* Initalize NTRU Context for decryption
 * in out d_ctx: NTRU context for decryption
 * in privatekey: private key in binary format (returned by NTRU_GenKeys)
 */
void NTRU_Decrypt_Init(NTRU_Decrypt_ctx *d_ctx, uint8_t *privatekey);

/* call this after correct decryption with NTRU_Decrypt
 * in out d_ctx: decryption context
 * in con: contains a single decrypted polynomial
 * out plaintext: decrypted binary data
 * out plainlength: length of decrypted binary data
 */
void NTRU_Decrypt_Postprocess_Update(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t **plaintext, int32_t *plainlength);

/* call this after last data block is postprocessed with 
 * NTRU_Decrypt_Postprocess_Update
 * in out d_ctx: decryption context
 * out plaintext: decrypted binary data
 * out plainlength: length of decrypted binary data
 */
void NTRU_Decrypt_Postprocess_Final(NTRU_Decrypt_ctx *d_ctx, uint8_t **plaintext, int32_t *plainlength);

/* Decryption process
 * in out d_ctx: decryption context
 * out con: contains decrypted polynomial, has to be postprocessed to retrieve
 *          original data
 * in encrypted: encrypted data (recieved from NTRU_Encrypt)
 * in enclength: length of encrypted data (recieved from NTRU_Encrypt)
 * return: success = 1, failure = 0 (in the 2nd case you have to rerequest that
 *         data block
 */
int32_t NTRU_Decrypt(NTRU_Decrypt_ctx *d_ctx, NTRU_Container *con, uint8_t *encrypted, int32_t enclength);


/* free all allocated memory in NTRU structs */
/* free num NTRU_Container at memory location con */
void freeContainer(NTRU_Container *con, int32_t num);
/* free encryption and decryption context */
void freeEncrypt_ctx(NTRU_Encrypt_ctx *e_ctx);
void freeDecrypt_ctx(NTRU_Decrypt_ctx *d_ctx);

#define NTRU_H
#endif
