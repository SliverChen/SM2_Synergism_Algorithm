/*
    经过测试，加密的时候出现了一些问题导致后续解密的时候报错: 点不在椭圆曲线上
    首先思考：加密的过程使用了公钥加密，在照抄的时候忘记修改一些步骤
    现在的加密过程是照搬的参考算法上的步骤，因此需要修改(主要目标)
*/


#include "./src/sm2.h"

#define __SM2_TEST_DEBUG__

int sm2_encrypt(uint8_t* cipher_text, unsigned int* cipher_len, EccPoint* p_publicKey, uint8_t p_random[NUM_ECC_DIGITS], uint8_t* plain_text, unsigned int plain_len)
{
    int i = 0;
    uint8_t PC = 0X04;
    uint8_t tmp = 0x00;
    uint8_t* k = new uint8_t[NUM_ECC_DIGITS];
    EccPoint C1;
    EccPoint Pb;
    EccPoint point2;
    EccPoint point2_revert;

    uint8_t* x2y2 = new uint8_t[NUM_ECC_DIGITS * 2];
    uint8_t* C2 = new uint8_t[65535];
    uint8_t* C3 = new uint8_t[NUM_ECC_DIGITS];
    sm3_context sm3_ctx;

    //A1:generate random number k;
        for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        k[i] = p_random[NUM_ECC_DIGITS - i - 1];
    }


    //A2:C1=[k]G;
    EccPoint_mult(&C1, &curve_G, k, NULL);
    for (i = 0; i < NUM_ECC_DIGITS / 2; i++)
    {
        tmp = C1.x[i];
        C1.x[i] = C1.x[NUM_ECC_DIGITS - i - 1];
        C1.x[NUM_ECC_DIGITS - i - 1] = tmp;

        tmp = C1.y[i];
        C1.y[i] = C1.y[NUM_ECC_DIGITS - i - 1];
        C1.y[NUM_ECC_DIGITS - i - 1] = tmp;
    }

    //A3:h=1;S=[h]Pb;
    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        Pb.x[i] = p_publicKey->x[NUM_ECC_DIGITS - i - 1];
        Pb.y[i] = p_publicKey->y[NUM_ECC_DIGITS - i - 1];
    }
    if (EccPoint_isZero(&Pb))
    {
        MES_ERROR("S at infinity...\n");
        return 0;
    }

    //A4:[k]Pb = (x2, y2);
    EccPoint_mult(&point2, &Pb, k, NULL);
    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        point2_revert.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revert.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

    //A5: t =KDF(x2||y2, klen)
    memcpy(x2y2, point2_revert.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revert.y, NUM_ECC_DIGITS);

    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, C2, plain_len);
    if (vli_isZero(C2))
    { /* If r == 0, fail (need a different random number). */
        MES_ERROR("the r equals zero, need a different random number\n");
        return 0;
    }

    //A6: C2 = M^t;
    for (i = 0; i < plain_len; i++)
    {
        C2[i] ^= plain_text[i];
    }

    //A7:C3 = Hash(x2, M, y2);
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revert.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, plain_len);
    sm3_update(&sm3_ctx, point2_revert.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, C3);

    //A8:C=C1||C3||C2
    cipher_text[0] = PC;
    *cipher_len = 1;
    memcpy(cipher_text + *cipher_len, C1.x, NUM_ECC_DIGITS * 2);
    *cipher_len += NUM_ECC_DIGITS * 2;
    memcpy(cipher_text + *cipher_len, C3, NUM_ECC_DIGITS);
    *cipher_len += NUM_ECC_DIGITS;
    memcpy(cipher_text + *cipher_len, C2, plain_len);
    *cipher_len += plain_len;

    return 1;
}

int sm2_decrypt_self(uint8_t *plain_text, unsigned int *plain_len, 
uint8_t *cipher_text, unsigned int cipher_len, 
uint8_t p_priKey[NUM_ECC_DIGITS])
{
    int i = 0,ret = 0;
    sm3_context sm3_ctx;
    EccPoint point2;
     EccPoint point2_revrt;
    uint8_t mac[NUM_ECC_DIGITS];
    uint8_t x2y2[NUM_ECC_DIGITS*2];
    EccPoint C1;
    uint8_t p_pvk[NUM_ECC_DIGITS];

    EccPoint *p_C1;
    uint8_t *p_C3;
    uint8_t *p_C2;
    int C2_len = 0;

    p_C1 = (EccPoint*)(cipher_text + 1);
    p_C3 = cipher_text + 65;
    p_C2 = cipher_text + 97;
    C2_len = cipher_len - 97;

    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        C1.x[i] = p_C1->x[NUM_ECC_DIGITS - i - 1];
        C1.y[i] = p_C1->y[NUM_ECC_DIGITS - i - 1];
        p_pvk[i] = p_priKey[NUM_ECC_DIGITS - i - 1];
    }

    ret = EccPoint_is_on_curve(C1);
    if(1 != ret)
    {
        MES_ERROR("C1 is not on curve\n");
        return 0;
    }

    //B2:h=1;S=[h]C1
    if(EccPoint_isZero(&C1))
    {
        MES_ERROR("S is at infinity..\n");
        return 0;
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("priKey: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",p_pvk[i]);
    }
    printf("\n");

    MES_INFO("cipher->C1.x: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",C1.x[i]);
    }
    printf("\n");

    MES_INFO("cipher->C1.y: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",C1.y[i]);
    }
    printf("\n");
#endif

    //B3:[dB]C1 = (x2,y2)
    EccPoint_mult(&point2,&C1,p_pvk,NULL);
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        point2_revrt.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revrt.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("point2.x: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",point2.x[i]);
    }
    printf("\n");

    MES_INFO("point2.y: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",point2.y[i]);
    }
#endif
    //B4: t=KDF(x2||y2,klen)
    memcpy(x2y2,point2_revrt.x,NUM_ECC_DIGITS);
    memcpy(x2y2+NUM_ECC_DIGITS,point2_revrt.y,NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2,NUM_ECC_DIGITS*2,plain_text,*plain_len);

    if(vli_isZero(plain_text))
    {
        MES_ERROR("r==0,need a different random number\n");
        return 0;
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("kdf out: ");
    for(i = 0;i<*plain_text;++i)
    {
        printf("%02X",plain_text[i]);
    }
    printf("\n");

    MES_INFO("C2: ");
    for(i = 0;i<C2_len;++i)
    {
        printf("%02X",p_C2[i]);
    }
    printf("\n");
#endif

    //B5: M' = C2 ^ t
    for(i = 0;i<C2_len;++i)
    {
        plain_text[i] ^= p_C2[i];
    }
    plain_text[*plain_len] = '\0';

    //B6: check Hash(x2 || M || y2) == C3
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx,point2_revrt.x,NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx,plain_text,*plain_len);
    sm3_update(&sm3_ctx,point2_revrt.y,NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx,mac);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("mac: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",mac[i]);
    }
    printf("\n");

    MES_INFO("cipher->M: ");
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",p_C3[i]);
    }
    printf("\n");
#endif

    if(0 != memcmp(p_C3,mac,NUM_ECC_DIGITS))
    {
        MES_ERROR("Hash(x2 || M || y2) not equals C3\n");
        return 0;
    }

    return 1;
}

void test_sm2_encrypt_decrypt()
{
    //1、设置加解密信息
    const char *plain_text = "Hello my friend";
    unsigned int plain_len = strlen(plain_text);

    //2、设置公私钥
    uint8_t *d1_str = NULL;
    uint8_t *d2_str = NULL;
    EccPoint p_publicKey;
    makeRandom(d1_str);
    makeRandom(d2_str);

    uint8_t d1_key[NUM_ECC_DIGITS];
    uint8_t d2_key[NUM_ECC_DIGITS];

    tohex(d1_str, d1_key, NUM_ECC_DIGITS);
    tohex(d2_str, d2_key, NUM_ECC_DIGITS);

    //P = d1d2G-G
    EccPoint d1d2G;
    EccPoint_mult(&d1d2G, &curve_G, d2_key, NULL);
    EccPoint_mult(&d1d2G, &p_publicKey, d1_key, NULL);

    uint8_t x1[NUM_ECC_DIGITS];
    uint8_t y1[NUM_ECC_DIGITS];
    uint8_t x2[NUM_ECC_DIGITS];
    uint8_t y2[NUM_ECC_DIGITS];

    vli_set(d1d2G.x, x1);
    vli_set(d1d2G.y, y1);
    vli_set(curve_G.x, x2);
    vli_set(curve_G.y, y2);

    //调用xycz_addc计算d1d2G-G，结果在(x2,y2)
    XYcZ_addC(x1, y1, x2, y2);

    vli_set(x2, p_publicKey.x);
    vli_set(y2, p_publicKey.y);


    //P = (d1d2-1)G

     uint8_t one[NUM_ECC_DIGITS] = {
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
         0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
         };
     uint8_t d1d2[NUM_ECC_DIGITS];
     uint8_t d1d2_1[NUM_ECC_DIGITS];
     vli_modMult(d1d2,d1_key,d2_key,curve_n);
     vli_modSub(d1d2_1,d1d2,one,curve_n);

    // EccPoint_mult(&p_publicKey,&curve_G,d1d2_1,NULL);


    //3、加密过程

    //3.1 生成随机数
    uint8_t p_random[NUM_ECC_DIGITS];
    uint8_t *rand_str = NULL;
    makeRandom(rand_str);
    tohex(rand_str, p_random, NUM_ECC_DIGITS);

    //3.2 加密
    uint8_t encdata[1024];    //密文
    unsigned int encdata_len; //密文长度
    uint8_t* plaintext = (uint8_t*)(plain_text);

    int ret = sm2_encrypt(encdata, &encdata_len, &p_publicKey,
                          p_random, plaintext, plain_len);

    MES_INFO("sm2_encrypt result:%d,  result's len: %d\n",ret,encdata_len);

    MES_INFO("encrypting result: ");
    for(int i = 0;i<encdata_len;++i)
    {
        printf("%02X",encdata[i]);
        if(1 == (i+1)%32)
            printf("\n");
    }
    printf("\n");
       

    //4、解密过程
    uint8_t p_out[NUM_ECC_DIGITS];
    unsigned int p_out_len = 0;
    ret = sm2_decrypt_self(
        p_out,&p_out_len,
        encdata,encdata_len,
        d1d2_1
        );
    
    MES_INFO("sm2_decrypt result: %d\n",ret);
    MES_INFO("plaintest is :%s\n",p_out);
}



int main()
{
    test_sm2_encrypt_decrypt();
    return 0;
}