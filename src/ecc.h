#ifndef HEADER_ECC_H
#define HEADER_ECC_H
#pragma once

#include"common.h"
#include"ecc_point.h"
#include"ecc_param.h"

#ifndef _cplusplus
extern "C"{
#endif 

/*
    Create a public / private key pair
    @param p_publicKey  the generated public key
    @param p_privateKey  the generated private key
    @param p_random  the random number to use to generate the key pair
    @returns 1 if the given point is valid, 0 if it is invalid
*/
int ecc_make_key(EccPoint *p_publicKey,uint8_t p_privateKey[NUM_ECC_DIGITS],uint8_t p_random[NUM_ECC_DIGITS]);


/*
    check the given point if is on the chosen elliptic curve
    @param p_publicKey the point to check
    @returns 1 if the given point is valid, 0 if it is invalid
*/
int ecc_valid_public_key(EccPoint* p_publicKey);

//------这里有个疑问，什么是共享私钥？


/*
    Convert an integer in standard octet representation to the native format.
    @param p_bytes the converted integer with the standard octet representation
    @param p_native the native integer value after converting
*/
void ecc_bytes2native(uint8_t p_bytes[NUM_ECC_DIGITS * 4],uint8_t P_native[NUM_ECC_DIGITS]);


/*
    Convert an integer in native format to the standard octet representation
    @param p_native the native integer value to be converted
    @param p_bytes  an integer in standard octet representation after converting
*/
void ecc_native2bytes(uint8_t p_native[NUM_ECC_DIGITS],uint8_t p_bytes[NUM_ECC_DIGITS*4]);



/*
    multiply in mod
    @param p_result the value after computing
    @param p_left the left value to be multiplied
    @param p_right the other value to be multiplied
    @param p_mod the mod of the defined ecc
*/
static void vli_modMult(
    uint8_t *p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod);




#ifndef _cplusplus
}
#endif

#endif //HEADER_ECC_H