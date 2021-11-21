/*
    the header of variable length integer computing
    (变长整数的运算)
    date: 2021 / 11 / 17
*/


#ifndef HEADER_VLI_COMPUTE_H
#define HEAEDER_VLI_COMPUTE_H
#pragma once

#include"common.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define EVEN(vli) (!(vli[0] & 1))

/*
 *   make the string with type 'uint8_t[] / uint8_t*' into the representation of hex \n
 *   @brief uint8_t str[] = "123123"  convert to  hex: uint8_t val[3] = {0x12, 0x31, 0x23}
 *   @param source the converted string
 *   @param result the representation of hex after converting
 *   @param len the length of the source string
 */
void tohex(const uint8_t* source,uint8_t* result,int len);

/*
    make the representation of hex into string type
    @brief source the representation of hex before converting
    @brief result the string after converting
    @param len the length of the representation of hex
*/
void tostr(const uint8_t* source,string& result,int len);

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
    counts the number of bits required for p_vli
*/
static unsigned int vli_numBits(uint8_t* p_vli);


/*
    set value from other value
    @param p_src the integer that will be refered
    @param p_dst the integer that will be set
*/
static void vli_set(uint8_t* p_src,uint8_t* p_dst);


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
static uint8_t vli_lshift(uint8_t* p_result,uint8_t* p_src,unsigned int p_shift);

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
static uint8_t vli_add(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);


/*
    computes minus
*/
static uint8_t vli_sub(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);


/*
    computes multiply
*/
static void vli_mult(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right);


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
    using p_result = (p_left * p_right) % curve_p
*/
static void vli_modMult_fast(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod);


/*
    calculate the mod in faster way
    @param p_result the value after calculating
    @param p_product the value that will be moded
*/
static void vli_mmod_fast(uint8_t* p_result,uint8_t* p_product);


/*
    compute the Inv of the value
    it means to calculate p into p^(-1)
    @param p_result the value after calculating
    @param p_input the value that will be calculated
    @param p_mod the mod of the value  
*/
static void vli_modInv(uint8_t* p_result,uint8_t* p_input,uint8_t* p_mod);

#ifdef ECC_SQUARE_FUNC

/*
    computes p_result = p_left^2;
*/
static void vli_square(uint8_t* p_result,uint8_t* p_left);

/*
    computes p_result = p_left^2 % curve_p
*/
static void vli_modSquare_fast(uint8_t* p_result,uint8_t* p_left);

#else //ECC_SQUARE_FUNC

#define vli_square(reuslt,left,size) vli_mult((result),(left),(left),(size))
#define vli_modSquare_fast(result,left) vli_modMult_fast((result),(left),(left))

#endif //ECC_SQUARE_FUNC



#ifdef __cplusplus
}
#endif //__cplusplus


#endif //HEADER_VLI_COMPUTE_H
