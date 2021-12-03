

#ifndef _MICRO_SM2_H_
#define _MICRO_SM2_H_

#ifdef __cplusplus //在C++编译环境下
extern "C"
{
#endif

#include <stdint.h>

/*Define to enable SM2 debug function*/
// #define __SM2_DEBUG__

/* 测试翻转的意义 */
// #define __SM2_TEST__

/* Define as 1 to enable ECDSA functions, 0 to disable.
 */
#define SM2_ECDSA 1

/* Optimization settings. Define as 1 to enable an optimization, 0 to disable it.
ECC_SQUARE_FUNC - If enabled, this will cause a specific function to be used for (scalar) squaring instead of the generic
                  multiplication function. Improves speed by about 8% .
*/
#define ECC_SQUARE_FUNC 1

/* Inline assembly options.
Currently we do not provide any inline assembly options. In the future we plan to offer
inline assembly for AVR and 8051.

Note: You must choose the appropriate option for your target architecture, or compilation will fail
with strange assembler messages.
*/
#define ecc_asm_none 0
#ifndef ECC_ASM
#define ECC_ASM ecc_asm_none
#endif

/* Currently only support 256-bit SM2 */
#define NUM_ECC_DIGITS 32

    typedef struct EccPoint
    {
        uint8_t x[NUM_ECC_DIGITS];
        uint8_t y[NUM_ECC_DIGITS];
    } EccPoint;

    typedef struct EccSig
    {
        uint8_t r[NUM_ECC_DIGITS];
        uint8_t s[NUM_ECC_DIGITS];
    } EccSig;

    /* ecc_make_key() function.
	Create a public/private key pair.

	You must use a new nonpredictable random number to generate each new key pair.

	Outputs:
		p_publicKey  - Will be filled in with the point representing the public key.
		p_privateKey - Will be filled in with the private key.

	Inputs:
		p_random - The random number to use to generate the key pair.

	Returns 1 if the key pair was generated successfully, 0 if an error occurred. If 0 is returned,
	try again with a different random number.
	*/
    int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

    /* ecc_valid_public_key() function.
	Determine whether or not a given point is on the chosen elliptic curve (ie, is a valid public key).

	Inputs:
		p_publicKey - The point to check.

	Returns 1 if the given point is valid, 0 if it is invalid.
	*/
    int ecc_valid_public_key(EccPoint *p_publicKey);

    /* ecdh_shared_secret() function.
	Compute a shared secret given your secret key and someone else's public key.

	Optionally, you can provide a random multiplier for resistance to DPA attacks. The random multiplier
	should probably be different for each invocation of ecdh_shared_secret().

	Outputs:
		p_secret - Will be filled in with the shared secret value.

	Inputs:
		p_publicKey  - The public key of the remote party.
		p_privateKey - Your private key.
		p_random     - An optional random number to resist DPA attacks. Pass in NULL if DPA attacks are not a concern.

	Returns 1 if the shared secret was computed successfully, 0 otherwise.

	Note: It is recommended that you hash the result of ecdh_shared_secret before using it for symmetric encryption or HMAC.
	If you do not hash the shared secret, you must call ecc_valid_public_key() to verify that the remote side's public key is valid.
	If this is not done, an attacker could create a public key that would cause your use of the shared secret to leak information
	about your private key. */
    int ecdh_shared_secret(uint8_t p_secret[NUM_ECC_DIGITS], EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

#if SM2_ECDSA

    //added by lhb
    int sm2_get_e(char *IDa, int IDLen, unsigned char *xa, unsigned char *ya, unsigned char *plaintext, unsigned int plainLen, unsigned char *e);
    /*sm2 签名接口*/
    int sm2_sign(EccSig *sig, uint8_t *msg, unsigned int msg_len, uint8_t *IDa, uint8_t IDa_len, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);
    /*sm2 验签接口*/
    int sm2_verify(EccSig *sig, uint8_t *msg, unsigned int msg_len, uint8_t *IDa, uint8_t IDa_len, EccPoint *p_pubk);
    /*sm2 加密接口*/
    int sm2_encrypt(uint8_t *cipher_text, unsigned int *cipher_len, EccPoint *p_publicKey, uint8_t p_random[NUM_ECC_DIGITS], uint8_t *plain_text, unsigned int plain_len);
    /*sm2 解密接口*/
    int sm2_decrypt(uint8_t *plain_text, unsigned int *plain_len, uint8_t *cipher_text, unsigned int cipher_len, uint8_t p_privateKey[NUM_ECC_DIGITS]);

    /* ecdsa_sign() function.
	Generate an ECDSA signature for a given hash value.

	Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
	this function along with your private key and a random number.
	You must use a new nonpredictable random number to generate each new signature.

	Outputs:
		r, s - Will be filled in with the signature values.

	Inputs:
		p_privateKey - Your private key.
		p_random     - The random number to use to generate the signature.
		p_hash       - The message hash to sign.

	Returns 1 if the signature generated successfully, 0 if an error occurred. If 0 is returned,
	try again with a different random number.
	*/
    int ecdsa_sign(uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS], uint8_t p_privateKey[NUM_ECC_DIGITS],
                   uint8_t p_random[NUM_ECC_DIGITS], uint8_t p_hash[NUM_ECC_DIGITS]);

    /* ecdsa_verify() function.
	Verify an ECDSA signature.

	Usage: Compute the hash of the signed data using the same hash as the signer and
	pass it to this function along with the signer's public key and the signature values (r and s).

	Inputs:
		p_publicKey - The signer's public key
		p_hash      - The hash of the signed data.
		r, s        - The signature values.

	Returns 1 if the signature is valid, 0 if it is invalid.
	*/
    int ecdsa_verify(EccPoint *p_publicKey, uint8_t p_hash[NUM_ECC_DIGITS], uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS]);

#endif /* ECC_ECDSA */

    /* ecc_bytes2native() function.
	Convert an integer in standard octet representation to the native format.

	Outputs:
		p_native - Will be filled in with the native integer value.

	Inputs:
		p_bytes - The standard octet representation of the integer to convert.
	*/
    void ecc_bytes2native(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS * 4]);

    /* ecc_native2bytes() function.
	Convert an integer in native format to the standard octet representation.

	Outputs:
		p_bytes - Will be filled in with the standard octet representation of the integer.

	Inputs:
		p_native - The native integer value to convert.
	*/
    void ecc_native2bytes(uint8_t p_bytes[NUM_ECC_DIGITS * 4], uint8_t p_native[NUM_ECC_DIGITS]);

#ifdef _WIN32
    __declspec(dllexport) int Encrpt_SM2(unsigned char *Message_original, int Length_of_Message, unsigned char *Message_encrypted);   //定义的加密函数接口
    __declspec(dllexport) int Decrypt_SM2(unsigned char *Message_Encrypted, int Length_of_Message, unsigned char *Message_Decrypted); //定义的解密函数接口
#else
int Encrpt_SM2(unsigned char *Message_original, int Length_of_Message, unsigned char *Message_encrypted);
int Decrypt_SM2(unsigned char *Message_Encrypted, int Length_of_Message, unsigned char *Message_Decrypted);
#endif //_WIN32

#ifdef __cplusplus //在C++编译环境下
}
#endif

#endif /* _MICRO_SM2_H_ */
