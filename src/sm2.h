/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include"vli_compute.h"
#include"sm3.h"
// #include"sm2Client.h"
// #include"sm2Server.h"

/*
    define to enable SM2 debug function
*/
#define __SM2_DEBUG__

/*
    Optimization settings:
    If enabled, this will cause a specific function 
    to be used multiplication function.
    Improves speed by about 8%
*/
#define __ECC_SQUARE_FUNC 1


/*
    Inline assembly options
    (no usage for now)
*/
#define ecc_asm_none 0
#ifndef ECC_ASM
    #define ECC_ASM ec_asm_none
#endif //ECC_ASM


/*
*   Create the random string between [1,n-1]
*   @param randStr the random string in 'uint8_t*' type that created
 */
void makeRandom(uint8_t*& randStr);

//since the string is defined in C++,
//we should make sure the environment it will be defined

#endif //HEAEDER_SM2_H