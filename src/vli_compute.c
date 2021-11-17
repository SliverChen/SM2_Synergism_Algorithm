#include"vli_compute.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus


void tohex(const uint8_t* source,uint8_t* result,int len)
{

}

static void vli_clear(uint8_t* p)
{

}

static int vli_isZero(uint8_t* p_vli)
{

}

static uint8_t vli_testBit(uint8_t* p_vli,unsigned int p_bit)
{

}

static unsigned int vli_numDigits(uint8_t* p_vli)
{

}

static void vli_set(uint8_t* p_src,uint8_t* p_dst)
{

}

static int vli_cmp(uint8_t* p_left,uint8_t* p_right)
{

}

static void vli_lshift(uint8_t* p_result,uint8_t* p_src,unsigned int p_shift)
{

}

static void vli_rshift(uint8_t* p_result,uint8_t* p_src,unsigned int p_shift)
{

}

static void vli_add(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right)
{

}

static void vli_sub(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right)
{

}

static void vli_mult(uint8_t* p_result,uint8_t* p_left,uint8_t* p_right)
{

}

static void vli_modAdd(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod
)
{

}

static void vli_modSub(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod
)
{

}

static void vli_modMult(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod
)
{

}

static void vli_modMult_fast(
    uint8_t* p_result,uint8_t* p_left,uint8_t* p_right,uint8_t* p_mod
)
{

}

static void vli_mmod_fast(uint8_t* p_result,uint8_t* p_product)
{

}

static void vli_modInv(uint8_t* p_result,uint8_t* p_input,uint8_t* p_mod)
{

}

#ifdef ECC_SQUARE_FUNC

static void vli_square(uint8_t* p_result,uint8_t* p_left)
{

}

static void vli_modSquare_fast(uint8_t* p_result,uint8_t* p_left)
{

}

#endif //ECC_SQUARE_FUNC



#ifdef __cplusplus
}
#endif //__cplusplus