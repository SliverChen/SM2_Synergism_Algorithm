/*
*   the header of the whole SM2 algorithm
*   including SM2Client and SM2Server
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include "common.h"
#include "sm3.h"
#include "vli_compute.h"
#include "ecc.h"
// #include"sm2Client.h"
// #include"sm2Server.h"

/*
    define to enable SM2 debug function
*/
#define __SM2_DEBUG__

#define __SM2_TEST_DEBUG__ 1

/*
    Inline assembly options
    (no usage for now)
*/
#define ecc_asm_none 0
#ifndef ECC_ASM
#define ECC_ASM ec_asm_none
#endif //ECC_ASM

#endif //HEAEDER_SM2_H