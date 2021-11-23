#include <stdio.h>
#include <stdlib.h>
#include "./src/sm2.h"

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
    EccPoint C1,S;
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
        MES_ERROR<<"C1 is not on curve\n";
        return 0;
    }

    //B2:h=1;S=[h]C1
    if(EccPoint_isZero(&C1))
    {
        MES_ERROR<<"S is at infinity..\n";
        return 0;
    }

    MES_INFO << "priKey: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",p_pvk[i]);
    }
    printf("\n");

    MES_INFO <<"cipher->C1.x: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",C1.x[i]);
    }
    printf("\n");

    MES_INFO << "cipher->C1.y: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",C1.y[i]);
    }
    printf("\n");

    //B3:[dB]C1 = (x2,y2)
    EccPoint_mult(&point2,&C1,p_pvk,NULL);
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        point2_revrt.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revrt.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

    MES_INFO << "point2.x: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",point2.x[i]);
    }
    printf("\n");

    MES_INFO <<"point2.y: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",point2.y[i]);
    }

    //B4: t=KDF(x2||y2,klen)
    memcpy(x2y2,point2_revrt.x,NUM_ECC_DIGITS);
    memcpy(x2y2+NUM_ECC_DIGITS,point2_revrt.y,NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2,NUM_ECC_DIGITS*2,plain_text,*plain_len);

    if(vli_isZero(plain_text))
    {
        MES_ERROR << "r==0,need a different random number\n";
        return 0;
    }

    MES_INFO << "kdf out: ";
    for(i = 0;i<*plain_text;++i)
    {
        printf("%02X",plain_text[i]);
    }
    printf("\n");

    MES_INFO <<"C2: ";
    for(i = 0;i<C2_len;++i)
    {
        printf("%02X",p_C2[i]);
    }
    printf("\n");


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

    MES_INFO <<"mac: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",mac[i]);
    }
    printf("\n");

    MES_INFO << "cipher->M: ";
    for(i = 0;i<NUM_ECC_DIGITS;++i)
    {
        printf("%02X",p_C3[i]);
    }
    printf("\n");

    if(0 != memcmp(p_C3,mac,NUM_ECC_DIGITS))
    {
        MES_ERROR << "Hash(x2 || M || y2) not equals C3\n";
        return 0;
    }

    return 1;
}

void test_sm2_encrypt_decrypt()
{
    //1、设置加解密信息
    uint8_t *plain_text = "Hello my friend";
    unsigned int plain_len = strlen(plain_text);

    //2、设置公私钥
    uint8_t *d1_str = nullptr;
    uint8_t *d2_str = nullptr;
    EccPoint p_publicKey;
    makeRandom(d1_str);
    makeRandom(d2_str);

    uint8_t d1_key[NUM_ECC_DIGITS];
    uint8_t d2_key[NUM_ECC_DIGITS];

    tohex(d1_str, d1_key, NUM_ECC_DIGITS);
    tohex(d2_str, d2_key, NUM_ECC_DIGITS);

    //P = d1d2G-G
    
    // EccPoint_mult(&d1d2G, &curve_G, d2_key, NULL);
    // EccPoint_mult(&d1d2G, &p_publicKey, d1_key, NULL);

    // uint8_t x1[NUM_ECC_DIGITS];
    // uint8_t y1[NUM_ECC_DIGITS];
    // uint8_t x2[NUM_ECC_DIGITS];
    // uint8_t y2[NUM_ECC_DIGITS];

    // vli_set(d1d2G.x, &x1);
    // vli_set(d1d2G.y, &y1);
    // vli_set(curve_G.x, &x2);
    // vli_set(curve_G.y, &y2);

    // //调用xycz_addc计算d1d2G-G，结果在(x2,y2)
    // XYcZ_addC(&x1, &y1, &x2, &y2);

    // vli_set(x2, &p_publicKey.x);
    // vli_set(y2, &p_publicKey.y);


    uint8_t one[NUM_ECC_DIGITS] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
        };
    uint8_t d1d2[NUM_ECC_DIGITS];
    uint8_t d1d2_1[NUM_ECC_DIGITS];
    vli_modMult(&d1d2,d1_key,d2_key,curve_n);
    vli_modSub(&d1d2_1,d1d2,one,curve_n);

    EccPoint_mult(&p_publicKey,curve_G,d1d2_1,NULL);


    //3、加密过程

    //3.1 生成随机数
    uint8_t p_random[NUM_ECC_DIGITS];
    uint8_t *rand_str = nullptr;
    makeRandom(rand_str);
    tohex(rand_str, &p_random, NUM_ECC_DIGITS);

    //3.2 加密
    uint8_t encdata[1024];    //密文
    unsigned int encdata_len; //密文长度

    int ret = sm2_encrypt(encdata, &encdata_len, &p_publicKey,
                          p_random, plain_text, plain_len);

    printf("sm2_encrypt result:%d\n",ret);

    printf("encrypting result: ");
    for(int i = 0;i<encdata_len;++i)
    {
        printf("%02X",encdata[i]);
        if(1 == (i+1)%32)
            printf("\n");
    }
    printf("\n");
       

    //4、解密过程
    uint8_t p_out[NUM_ECC_DIGITS];
    int p_out_len = 0;
    ret = sm2_decrypt_self(
        p_out,&p_out_len,
        &encdata,encdata_len,
        d1d2_1
        );
    
    printf("sm2_decrypt result: %d\n",ret);
    printf("plaintest is :%s\n",p_out);
}



int main()
{
    test_sm2_encrypt_decrypt();
    return 0;
}