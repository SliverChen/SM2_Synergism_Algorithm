/*
*   the header of the computing in ECC
*   Progress: find the function that will use C++ grammar
*/

#ifndef HEADER_ECC_H
#define HEADER_ECC_H
#pragma once

#include "common.h"
#include "ecc_point.h"
#include "ecc_param.h"
#include "vli_compute.h"

//the following function 'makeRandom' is defined in C++ environment

/*
*   Create the random string between [1,n-1]
*   @param randStr the random string in 'uint8_t*' type that created
 */
void makeRandom(uint8_t *&randStr);

#ifdef __cplusplus
extern "C"
{
#endif

    /*
    Convert an integer in standard octet representation to the native format.
    @param p_bytes the converted integer with the standard octet representation
    @param p_native the native integer value after converting
*/
    void ecc_bytes2native(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS * 4]);

    /*
    Convert an integer in native format to the standard octet representation
    @param p_native the native integer value to be converted
    @param p_bytes  an integer in standard octet representation after converting
*/
    void ecc_native2bytes(uint8_t p_bytes[NUM_ECC_DIGITS * 4], uint8_t p_native[NUM_ECC_DIGITS]);

    /* ecc point operations */

    /*
    check if point is infinity point or not
    @param p_point the point that will be checked
    @return 1 if p_point is at infinity,0 otherwise
*/
    int EccPoint_isZero(EccPoint *p_point);

    /*
    check if point is on curve
    @return 1 if point is on curve, 0 otherwise
*/
    int EccPoint_is_on_curve(EccPoint p_point);

    /*
    Double in place
    @param X1 the X-axis component
    @param Y1 the Y-axis component
    @param Z1 the Z-axis component
*/
    void EccPoint_double_jacobian(uint8_t *X1, uint8_t *Y1, uint8_t *Z1);

    /*
    Modify (x1,y1) => (x1 * z^2, y1 * z^3)
*/
    void apply_z(uint8_t *X1, uint8_t *Y1, uint8_t *Z1);

    /*
    Given P(x1,y1), calculate 2P=>(x2,y2)
    @param (X1,Y1) the point refers to P
    @param (X2,Y2) the point after calculating
*/
    void XYcZ_initial_double(uint8_t *X1, uint8_t *Y1,
                             uint8_t *X2, uint8_t *Y2, uint8_t *p_initialZ);

    /*
    calculate point1(x1,y1) add point2(x2,y2)
    the result is in the point2
    */
    void XYcZ_add(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2);

    /*
    compute point add and point minus.

    Instruction: 
        P+Q = (x3,y3,z); P-Q = (x3',y3',z).
    
    InPut:
        (X1,Y1): one of the point to be calculated.
        (X2,Y2): one of the point to be calculated.
    
    OutPut:
        X1(x3): the x-axis value after adding
        Y1(y3): the y-axis value after adding
        X2(x3'): the x-axis value after minusing
        Y2(y3'): the y-axis value after minusing
*/
    void XYcZ_addC(uint8_t *X1, uint8_t *Y1, uint8_t *X2, uint8_t *Y2);

    /*
    compute mutiply between two of the EccPoint
*/
    void EccPoint_mult(EccPoint *p_result, EccPoint *p_point,
                       uint8_t *p_scalar, uint8_t *p_initialZ);

    /*
    Create a public / private key pair
    @param p_publicKey  the generated public key
    @param p_privateKey  the generated private key
    @param p_random  the random number to use to generate the key pair
    @returns 1 if the given point is valid, 0 if it is invalid
*/
    int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

    /*
    check the given point if is on the chosen elliptic curve
    @param p_publicKey the point to check
    @returns 1 if the given point is valid, 0 if it is invalid
*/
    int ecc_valid_public_key(EccPoint *p_publicKey);

    /*
    calculate the shared secret
*/
    int ecdh_shared_secret(uint8_t p_secret[NUM_ECC_DIGITS], EccPoint *p_publicKey,
                           uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //HEADER_ECC_H