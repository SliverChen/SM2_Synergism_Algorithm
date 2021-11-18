#include "vli_compute.h"
#include "ecc_param.h"

#ifdef __cplusplus
extern "C"
{
#endif //__cplusplus

    void tohex(const uint8_t *source, uint8_t *result, int len)
    {
        uint8_t h1, h2;
        uint8_t s1, s2;
        int i;
        for (i = 0; i < len; ++i)
        {
            h1 = source[2 * i];
            h2 = source[2 * i + 1];
            s1 = toupper(h1) - '0';
            if (s1 > 9)
                s1 = s1 - ('A' - ':');
            s2 = toupper(h2) - '0';
            if (s2 > 9)
                s2 = s2 - ('A' - ':');

            result[i] = s1 * 16 + s2;
        }
    }

    static void vli_clear(uint8_t *p_vli)
    {
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
            p_vli[i] = 0;
    }

    static int vli_isZero(uint8_t *p_vli)
    {
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
            if (p_vli[i])
                return 0;
        return 1;
    }

    static uint8_t vli_testBit(uint8_t *p_vli, unsigned int p_bit)
    {
        return (p_vli[p_bit / 8] & (1 << (p_bit % 8)));
    }

    static unsigned int vli_numDigits(uint8_t *p_vli)
    {
        int i = NUM_ECC_DIGITS - 1;
        while (i >= 0 && p_vli[i] == 0)
            --i;
        return (i + 1);
    }

    static unsigned int vli_numDigits(uint8_t *p_vli)
    {
        unsigned int i;
        uint8_t l_digit;
        unsigned int l_numDigits = vli_numDigits(p_vli);
        if (l_numDigits == 0)
            return 0;

        l_digit = p_vli[l_numDigits - 1];
        for (i = 0; l_digit; ++i)
            l_digit >>= 1;

        return ((l_numDigits - 1) * 8 + i);
    }

    static void vli_set(uint8_t *p_src, uint8_t *p_dst)
    {
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
            p_dst[i] = p_src[i];
    }

    static int vli_cmp(uint8_t *p_left, uint8_t *p_right)
    {
        int i;
        for (i = NUM_ECC_DIGITS - 1; i >= 0; --i)
        {
            if (p_left[i] > p_right[i])
                return 1;
            else if (p_left[i] < p_right[i])
                return -1;
        }
        return 0;
    }

    static uint8_t vli_lshift(uint8_t *p_result, uint8_t *p_src, unsigned int p_shift)
    {
        uint8_t l_carry = 0;
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
        {
            uint8_t l_temp = p_src[i];
            p_result[i] = (l_temp << p_shift) | l_carry;
            l_carry = l_temp >> (8 - p_shift);
        }
        return l_carry;
    }

    static void vli_rshift(uint8_t *p_vli)
    {
        uint8_t *l_end = p_vli;
        uint8_t l_carry = 0;

        p_vli += NUM_ECC_DIGITS;
        while (p_vli-- > l_end)
        {
            uint8_t l_temp = *p_vli;
            *p_vli = (l_temp >> 1) | l_carry;
            l_carry = l_temp << 7;
        }
    }

    static uint8_t vli_add(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
    {
        uint8_t l_carry = 0;
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
        {
            uint8_t l_sum = p_left[i] + p_right[i] + l_carry;
            if (l_sum != p_left[i])
            {
                l_carry = (l_sum < p_left[i]);
            }
            p_result[i] = l_sum;
            return l_carry;
        }
    }

    static uint8_t vli_sub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
    {
        uint8_t l_borrow = 0;
        unsigned int i;
        for (i = 0; i < NUM_ECC_DIGITS; ++i)
        {
            uint8_t l_diff = p_left[i] - p_right[i] - l_borrow;
            if (l_diff != p_left[i])
                l_borrow = (l_diff > p_left[i]);
            p_result[i] = l_diff;
        }
        return l_borrow;
    }

    static void vli_mult(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right)
    {
        uint16_t r01 = 0;
        uint8_t r2 = 0;

        unsigned int i, k;

        for (k = 0; k < NUM_ECC_DIGITS - 1; ++k)
        {
            unsigned int l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
            for (i = l_min; i <= k && i < NUM_ECC_DIGITS; ++i)
            {
                uint16_t l_product = (uint16_t)p_left[i] * p_right[k - i];
                r01 += l_product;
                r2 += (r01 < l_product);
            }
            p_result[k] = (uint8_t)r01;
            r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
            r2 = 0;
        }

        p_result[NUM_ECC_DIGITS * 2 - 1] = (uint16_t)r01;
    }

    static void vli_modAdd(
        uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
    {
        uint8_t l_carry = vli_add(p_result, p_left, p_right);
        if (l_carry || vli_cmp(p_result, p_mod) >= 0)
        {
            vli_sub(p_result, p_result, p_mod);
        }
    }

    static void vli_modSub(
        uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
    {
        uint8_t l_borrow = vli_sub(p_result, p_left, p_right);
        if (l_borrow)
        {
            vli_add(p_result, p_result, p_mod);
        }
    }

    static void vli_modMult_fast(
        uint8_t *p_result, uint8_t *p_left, uint8_t *p_right, uint8_t *p_mod)
    {
        uint8_t l_product[2 * NUM_ECC_DIGITS];
        vli_mult(l_product, p_left, p_right);
        vli_mmod_fast(p_result, l_product);
    }

    static void vli_mmod_fast(uint8_t *p_result, uint8_t *p_product)
    {
        uint8_t l_tmp1[NUM_ECC_DIGITS];
        uint8_t l_tmp2[NUM_ECC_DIGITS];
        uint8_t l_tmp3[NUM_ECC_DIGITS];
        int l_carry = 0;

        vli_set(p_result, p_product);
        vli_clear(l_tmp1);
        vli_clear(l_tmp2);
        vli_clear(l_tmp3);

        //calculate Y0
        l_tmp1[0] = l_tmp1[12] = l_tmp1[28] = p_product[32];
        l_tmp1[1] = l_tmp1[13] = l_tmp1[29] = p_product[33];
        l_tmp1[2] = l_tmp1[14] = l_tmp1[30] = p_product[34];
        l_tmp1[3] = l_tmp1[15] = l_tmp1[31] = p_product[35];
        l_tmp2[8] = p_product[32];
        l_tmp2[9] = p_product[33];
        l_tmp2[10] = p_product[34];
        l_tmp2[11] = p_product[35];
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry -= vli_sub(p_result, p_result, l_tmp2);

        //calculate Y1
        l_tmp1[0] = l_tmp1[4] = l_tmp1[16] = l_tmp1[28] = p_product[36];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[17] = l_tmp1[29] = p_product[37];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[18] = l_tmp1[30] = p_product[38];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[19] = l_tmp1[31] = p_product[39];
        l_tmp1[12] = l_tmp1[13] = l_tmp1[14] = l_tmp1[15] = 0;
        l_tmp2[8] = p_product[36];
        l_tmp2[9] = p_product[37];
        l_tmp2[10] = p_product[38];
        l_tmp2[11] = p_product[39];
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry -= vli_sub(p_result, p_result, l_tmp2);

        //calculate Y2
        l_tmp1[0] = l_tmp1[4] = l_tmp1[20] = l_tmp1[28] = p_product[40];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[21] = l_tmp1[29] = p_product[41];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[22] = l_tmp1[30] = p_product[42];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[23] = l_tmp1[31] = p_product[43];
        l_tmp1[16] = l_tmp1[17] = l_tmp1[18] = l_tmp1[19] = 0;
        l_carry += vli_add(p_result, p_result, l_tmp1);

        //calculate Y3
        l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[24] = l_tmp1[28] = p_product[44];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[25] = l_tmp1[29] = p_product[45];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[26] = l_tmp1[30] = p_product[46];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[27] = l_tmp1[31] = p_product[47];
        l_tmp1[20] = l_tmp1[21] = l_tmp1[22] = l_tmp1[23] = 0;
        l_carry += vli_add(p_result, p_result, l_tmp1);

        //calculate Y4
        l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[28] = l_tmp3[28] = p_product[48];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[29] = l_tmp3[29] = p_product[49];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[30] = l_tmp3[30] = p_product[50];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[31] = l_tmp3[31] = p_product[51];
        l_tmp1[24] = l_tmp1[25] = l_tmp1[26] = l_tmp1[27] = 0;
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry += vli_add(p_result, p_result, l_tmp3);

        //calculate Y5
        l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[28] = p_product[52];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[29] = p_product[53];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[30] = p_product[54];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[31] = p_product[55];
        l_tmp2[8] = p_product[52];
        l_tmp2[9] = p_product[53];
        l_tmp2[10] = p_product[54];
        l_tmp2[11] = p_product[55];
        l_tmp3[0] = l_tmp3[12] = l_tmp3[28] = p_product[52];
        l_tmp3[1] = l_tmp3[13] = l_tmp3[29] = p_product[53];
        l_tmp3[2] = l_tmp3[14] = l_tmp3[30] = p_product[54];
        l_tmp3[3] = l_tmp3[15] = l_tmp3[31] = p_product[55];
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry += vli_add(p_result, p_result, l_tmp3);
        l_carry -= vli_sub(p_result, p_result, l_tmp2);

        //calculate Y6
        l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[24] = l_tmp1[28] = p_product[56];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[25] = l_tmp1[29] = p_product[57];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[26] = l_tmp1[30] = p_product[58];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[27] = l_tmp1[31] = p_product[59];
        l_tmp2[8] = p_product[56];
        l_tmp2[9] = p_product[57];
        l_tmp2[10] = p_product[58];
        l_tmp2[11] = p_product[59];
        l_tmp3[0] = l_tmp3[4] = l_tmp3[16] = l_tmp3[28] = p_product[56];
        l_tmp3[1] = l_tmp3[5] = l_tmp3[17] = l_tmp3[29] = p_product[57];
        l_tmp3[2] = l_tmp3[6] = l_tmp3[18] = l_tmp3[30] = p_product[58];
        l_tmp3[3] = l_tmp3[7] = l_tmp3[19] = l_tmp3[31] = p_product[59];
        l_tmp3[12] = l_tmp3[13] = l_tmp3[14] = l_tmp3[15] = 0;
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry += vli_add(p_result, p_result, l_tmp3);
        l_carry -= vli_sub(p_result, p_result, l_tmp2);

        //calculate Y7
        l_tmp1[0] = l_tmp1[4] = l_tmp1[12] = l_tmp1[16] = l_tmp1[20] = l_tmp1[24] = l_tmp1[28] = p_product[60];
        l_tmp1[1] = l_tmp1[5] = l_tmp1[13] = l_tmp1[17] = l_tmp1[21] = l_tmp1[25] = l_tmp1[29] = p_product[61];
        l_tmp1[2] = l_tmp1[6] = l_tmp1[14] = l_tmp1[18] = l_tmp1[22] = l_tmp1[26] = l_tmp1[30] = p_product[62];
        l_tmp1[3] = l_tmp1[7] = l_tmp1[15] = l_tmp1[19] = l_tmp1[23] = l_tmp1[27] = l_tmp1[31] = p_product[63];
        l_tmp3[0] = l_tmp3[4] = l_tmp3[20] = p_product[60];
        l_tmp3[1] = l_tmp3[5] = l_tmp3[21] = p_product[61];
        l_tmp3[2] = l_tmp3[6] = l_tmp3[22] = p_product[62];
        l_tmp3[3] = l_tmp3[7] = l_tmp3[23] = p_product[63];
        l_tmp3[16] = l_tmp3[17] = l_tmp3[18] = l_tmp3[19] = l_tmp3[28] = l_tmp3[29] = l_tmp3[30] = l_tmp3[31] = 0;
        l_tmp2[28] = p_product[60];
        l_tmp2[29] = p_product[61];
        l_tmp2[30] = p_product[62];
        l_tmp2[31] = p_product[63];
        l_tmp2[8] = l_tmp2[9] = l_tmp2[10] = l_tmp2[11] = 0;
        l_carry += vli_lshift(l_tmp2, l_tmp2, 1);
        l_carry += vli_add(p_result, p_result, l_tmp1);
        l_carry += vli_add(p_result, p_result, l_tmp3);
        l_carry += vli_add(p_result, p_result, l_tmp2);

        if (l_carry < 0)
        {
            do
            {
                l_carry += vli_add(p_result, p_result, curve_p);
            } while (l_carry < 0);
        }
        else
        {
            while (l_carry || vli_cmp(curve_p, p_result) != 1)
            {
                l_carry -= vli_sub(p_result, p_result, curve_p);
            }
        }
    }

    static void vli_modInv(uint8_t *p_result, uint8_t *p_input, uint8_t *p_mod)
    {
        uint8_t a[NUM_ECC_DIGITS], b[NUM_ECC_DIGITS], u[NUM_ECC_DIGITS], v[NUM_ECC_DIGITS];
        uint8_t l_carry;

        vli_set(a, p_input);
        vli_set(b, p_mod);
        vli_clear(u);
        u[0] = 1;
        vli_clear(v);

        int l_cmpResult;
        while ((l_cmpResult = vli_cmp(a, b)) != 0)
        {
            l_carry = 0;
            if (EVEN(a))
            {
                vli_rshift(a);
                if (!EVEN(u))
                    l_carry = vli_add(u, u, p_mod);
                vli_rshift(u);
                if (l_carry)
                {
                    u[NUM_ECC_DIGITS - 1] |= 0x80;
                }
            }
            else if (EVEN(b))
            {
                vli_rshift(b);
                if (!EVEN(v))
                    l_carry = vli_add(v, v, p_mod);
                vli_rshift(v);
                if (l_carry)
                    v[NUM_ECC_DIGITS - 1] |= 0x80;
            }
            else if (l_cmpResult > 0)
            {
                vli_sub(a, a, b);
                vli_rshift(a);
                if (vli_cmp(u, v) < 0)
                    vli_add(u, u, p_mod);
                vli_sub(u, u, v);
                if (!EVEN(u))
                    l_carry = vli_add(u, u, p_mod);
                vli_rshift(u);
                if (l_carry)
                {
                    u[NUM_ECC_DIGITS - 1] |= 0x80;
                }
            }
            else
            {
                vli_sub(b, b, a);
                vli_rshift(b);
                if (vli_cmp(v, u) < 0)
                {
                    vli_add(v, v, p_mod);
                }
                vli_sub(v, v, u);
                if (!EVEN(v))
                {
                    l_carry = vli_add(v, v, p_mod);
                }
                vli_rshift(v);
                if (l_carry)
                {
                    v[NUM_ECC_DIGITS - 1] |= 0x80;
                }
            }
        }
        vli_set(p_result, u);
    }

#ifdef ECC_SQUARE_FUNC

    static void vli_square(uint8_t *p_result, uint8_t *p_left)
    {
        uint16_t r01 = 0;
        uint8_t r2 = 0;

        unsigned int i, k;
        for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; ++k)
        {
            unsigned int l_min = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
            for (i = l_min; i <= k && i <= k - i; ++i)
            {
                uint16_t l_product = (uint16_t)p_left[i] * p_left[k - i];
                if (i < k - i)
                {
                    r2 += l_product >> 15;
                    l_product *= 2;
                }
                r01 += l_product;
                r2 += (r01 < l_product);
            }
            p_result[k] = (uint8_t)r01;
            r01 = (r01 >> 8) | (((uint16_t)r2) << 8);
            r2 = 0;
        }

        p_result[NUM_ECC_DIGITS * 2 - 1] = (uint8_t)r01;
    }

    static void vli_modSquare_fast(uint8_t *p_result, uint8_t *p_left)
    {
        uint8_t l_product[2 * NUM_ECC_DIGITS];
        vli_square(l_product, p_left);
        vli_mmod_fast(p_result, l_product);
    }

#endif //ECC_SQUARE_FUNC

#ifdef __cplusplus
}
#endif //__cplusplus