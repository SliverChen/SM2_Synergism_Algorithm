#ifndef HEADER_ECC_POINT_H
#define HEADER_ECC_POINT_H
#pragma once;

#include"common.h"

#ifndef _cplusplus
extern "C" {
#endif //_cplusplus


typedef struct ECCPOINT{
    uint8_t x[NUM_ECC_DIGITS];
    uint8_t y[NUM_ECC_DIGITS];
}EccPoint;



typedef struct ECCSIG{
    uint8_t r[NUM_ECC_DIGITS];
    uint8_t s[NUM_ECC_DIGITS];
}EccSig;



#ifndef _cplusplus
}
#endif //_cplusplus

#endif //HEADER_ECC_POINT_H