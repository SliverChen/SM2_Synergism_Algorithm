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


/* the function of 8-bit values */

/*
    clear the value
    @param p_vli the value that will be cleared
*/
static void vli_clear(uint8_t* p_vli);


/*
    check the value if is zero
    @param p_vli the value that will be checked
    @return 1 if the value is zero, 0 otherwise.
*/
static int vli_isZero(uint8_t* p_vli);


/*
    check the value if is valid
    @param p_vli the value that will be checked
    @return nonzero if bit p_bit of p_vli is set.
*/
static uint8_t vli_testBit(uint8_t *p_vli,unsigned int p_bit);


/*
    counts the number of 8-bit digits in p_vli
    @param p_vli the value that will be counted
    @return the number of 8-bit digits in p_vli
*/
static unsigned int vli_numDigits(uint8_t* p_vli);

/*
    set value from other value
    @param p_src the integer that will be refered
    @param p_dst the integer that will be set
*/
static void vli_set(uint8_t* p_src,uint8_t* p_dst)


/*
    compare both of values
    @param p_left one value
    @param p_right the other value
    @return 1 if p_left>p_right, 0 if p_left==p_right, -1 if p_left < p_right
*/
static int vli_cmp(uint8_t* p_left,uint8_t* p_right);

/*
    computes value << c
    @param p_result the value after computing
    @param p_src the value that will be computed
    @param p_shift the number of bits shifted left
*/
static void vli_lshift(uint8_t* p_result,uint8_t* p_src,unsigned int p_shift);

/*
    computes value >> c
    @param p_result the value after computing
    @param p_src the value that will be computed
    @param p_shift the number of bits shifted right
*/
static void vli_rshift(uint8_t* p_result,uint8_t* p_src,unsigned int p_right);


/*
    computes adding
*/
static void vli_add(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);


/*
    computes minus
*/
static void vli_sub(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);


/*
    computes multiply
*/
static void vli_mult(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);



/* the function that computed in mod */

/*
    multiply in mod
    @param p_result the value after computing
    @param p_left the left value to be multiplied
    @param p_right the other value to be multiplied
    @param p_mod the mod of the defined ecc
*/
static void vli_modMult(
    uint8_t *p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod);

/*
    multiply in mod with faster way
*/
static void vli_modMult_fast(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod
);

#if ECC_SQUARE_FUNC

/*
    computing the value in square
    s.t. value * value
    @param p_result the result of computing
    @param p_src the value participated in computing
*/
static void vli_square(uint8_t* p_result,uint8_t* p_src);

/*
    computing the value in square with faster way
*/
static void vli_modSquare_fast(uint8_t* p_result,uint8_t* p_src);

#else //ECC_SQUARE_FUNC

#define vli_square(result,left,size) vli_mult

#endif //ECC_SQUARE_FUNC

/*
    add in mod
    @param p_result the value after computing
    @param p_left the left value to be added
    @param p_right the other value to be added
    @param p_mod the mod of the defined ecc
*/
static void vli_modAdd(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod);


/*
    minus in mod
    @param p_result the value after computing
    @param p_left the left value to be minus
    @param p_right the right value to be minus
    @param p_mod the mod of the defined ecc
*/
static void vli_modSub(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod);


/*

*/



#ifndef _cplusplus
}
#endif

#endif //HEADER_ECC_H