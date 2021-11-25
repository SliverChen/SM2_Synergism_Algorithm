/*
    经过测试，加密的时候出现了一些问题导致后续解密的时候报错: 点不在椭圆曲线上
    思考：
        1、加密的过程使用了公钥加密，公钥的形式是什么(d1d2G-G)
        2、解密的过程使用了私钥解密，私钥的形式是什么
            (不是子私钥d1或d2，而是总的私钥的形式)
           猜想是d1d2-1但是测试不通过，接下来测试d1d2作为私钥
        3、解密的时候(x2,y2)的值是否经过了修改，是否用的是自定义的公式

    通过观察与测试，发现每次测试的时候公钥得到的结果都是一样的
    推测是公钥的计算公式出了问题
    经过排查，问题出在加密的C1计算中

    目前进度(11.24 15:51):
        目前将所有的函数与参考算法对照了一遍，修改后再对照一遍确认无误
        但是最开始的计算公钥的地方有点奇怪，得到的公钥的x和y都是64个C组成
        在执行ecc_valid_public_key()的时候返回的是0，说明公钥是无效的
        重点关注到公钥的计算上(因为是自定义的步骤，多少跟参考算法有些出入)
    
    目前进度(11.24 16:05):
        经过排查修改了一处错误，公钥的生成没有出现太大的问题
        但是在解密的时候总是会提示C1不在曲线上
        尝试在所有计算点过程的后面加上一个判断:判断该点是否在曲线上

    目前进度(11.24 16:20):
        经过输出信息，获知在加密时候的C1就不在曲线上
        如果在解密的时候无视这个错误，那么后续hash(x2||M||y2)也无法等于C3
        生成C1唯一途径就是随机数k乘上曲线的基点
        问题可能是随机数k的选取需要一些限制
        尝试不断生成随机数k，然后计算C1=kG，判断C1是否在曲线上，如果不在就重新生成

    目前进度(11.24 16:45):
        尝试不断生成随机数k，然后计算C1=kG，直到C1在曲线上，生成结束
        但是经过三分钟的调试发现没有随机数能够满足在曲线上的情况
        可能还需要考虑一些特殊的条件来约束随机数

        但是也有可能是这个公式有些问题，对于自定义的私钥格式可能存在不一样的计算过程
        这个需要结合SM2算法的理论步骤来去理解

        卡在这个进度也说明了SM2算法的理论基础也是比较重要的
        这样就不会在某个基础的地方卡半天
    
    目前进度(11.25 8:31):
        为了验证昨天的想法，大概要做以下几点：
        1、理解SM2算法的公式计算
        2、证明公钥计算公式的有效性
        3、代码计算的可行性

    目前进度(11.25 9:52):
        通过修改随机数生成的代码时发现vli_cmp()在比较随机数大小的时候是从最后一个数开始的
        也就是说，vli_xx的计算最开始的那一端是最低位,而最后面的是最高位
        这也大致说明了为什么有些地方需要翻转
        那么在计算d1d2-1的时候，这个1的设计应该是{0x01,0x00,...,0x00}而不是{0x00,...,0x00,0x01}

    目前进度(11.25 10:25):
        通过仔细观察源码的实现细节，可以发现，对于vli_modxx的计算，后面的p_mod选取的都是curve_p而不是curve_n
        curve_n的出现在源码中是valid_privateKey的时候描述的一段话
        "生成的私钥需要保证其范围在[1,n-1]之间" 其中使用的n就是curve_n
        也就是说后续在碰到vli_modxx计算的时候选取的是curve_p，在其他情况下都按照正常的思路选择curve_n来比较大小

        同时无论如何修改都无法满足C1=[k]G在椭圆曲线上，目前这个k的生成限制是vli_cmp(curve_n,k)==1 && !vli_isZero(k)
        或许随机数k还有其他限制条件没有考虑进来，需要后续进行深入的研究和不断测试。
*/

#include "./src/sm2.h"

int sm2_encrypt(uint8_t *cipher_text, unsigned int *cipher_len, EccPoint *p_publicKey, uint8_t p_random[NUM_ECC_DIGITS], uint8_t *plain_text, unsigned int plain_len)
{
    int i = 0;
    uint8_t PC = 0X04;
    uint8_t tmp = 0x00;
    uint8_t *k = new uint8_t[NUM_ECC_DIGITS];
    EccPoint C1;
    EccPoint Pb;
    EccPoint point2;
    EccPoint point2_revert;

    uint8_t *x2y2 = new uint8_t[NUM_ECC_DIGITS * 2];
    uint8_t *C2 = new uint8_t[65535];
    uint8_t *C3 = new uint8_t[NUM_ECC_DIGITS];
    sm3_context sm3_ctx;

    //A1:generate random number k;
    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        k[i] = p_random[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the random number k is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", k[i]);
    }
    printf("\n");
#endif //_SM2_TEST_DEBUG__

    //A2:C1=[k]G;
    EccPoint_mult(&C1, &curve_G, k, NULL);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("after EccPoint_mult, C1.x values: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");

    MES_INFO("after EccPoint_mult, C1.y values: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");

    if (EccPoint_is_on_curve(C1))
    {
        MES_INFO("before exchange,the C1 is on the curve\n");
    }
    else
    {
        MES_ERROR("before exchange,the C1 is not on the curve\n");
    }

#endif // __SM2_TEST_DEBUG__

    for (i = 0; i < NUM_ECC_DIGITS / 2; i++)
    {
        tmp = C1.x[i];
        C1.x[i] = C1.x[NUM_ECC_DIGITS - i - 1];
        C1.x[NUM_ECC_DIGITS - i - 1] = tmp;

        tmp = C1.y[i];
        C1.y[i] = C1.y[NUM_ECC_DIGITS - i - 1];
        C1.y[NUM_ECC_DIGITS - i - 1] = tmp;
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the encrypting C1.x is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");
    MES_INFO("the encrypting C1.y is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");

    if (EccPoint_is_on_curve(C1))
    {
        MES_INFO("the encrypting C1 is on the curve\n");
    }
    else
    {
        MES_ERROR("the encrypting C1 is not on the curve\n");
    }
#endif //__SM2_TEST_DEBUG__

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

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the encrypting point2.x is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2_revert.x[i]);
    }
    printf("\n");
    MES_INFO("the encrypting point2.y is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2_revert.y[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    //A5: t =KDF(x2||y2, klen)
    memcpy(x2y2, point2_revert.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revert.y, NUM_ECC_DIGITS);

    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, C2, plain_len);
    if (vli_isZero(C2))
    { /* If r == 0, fail (need a different random number). */
        MES_ERROR("the r equals zero, need a different random number\n");
        return 0;
    }
    C2[plain_len] = '\0';

    //A6: C2 = M^t;
    for (i = 0; i < plain_len; i++)
    {
        C2[i] ^= plain_text[i];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the encrypting C2 is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C2[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    //A7:C3 = Hash(x2, M, y2);
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revert.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, plain_len);
    sm3_update(&sm3_ctx, point2_revert.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, C3);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the encrypting C3 is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C3[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    //A8:C=C1||C3||C2
    cipher_text[0] = PC;
    *cipher_len = 1;
    memcpy(cipher_text + *cipher_len, C1.x, NUM_ECC_DIGITS * 2);
    *cipher_len += NUM_ECC_DIGITS * 2;
    memcpy(cipher_text + *cipher_len, C3, NUM_ECC_DIGITS);
    *cipher_len += NUM_ECC_DIGITS;
    memcpy(cipher_text + *cipher_len, C2, plain_len);
    *cipher_len += plain_len;

    FREEARRAY(k);
    FREEARRAY(x2y2);
    FREEARRAY(C2);
    FREEARRAY(C3);

    return 1;
}

int sm2_decrypt_self(uint8_t *plain_text, unsigned int *plain_len,
                     uint8_t *cipher_text, unsigned int cipher_len,
                     uint8_t p_priKey[NUM_ECC_DIGITS])
{
    int i = 0, ret = 0;
    sm3_context sm3_ctx;
    EccPoint point2;
    EccPoint point2_revrt;
    uint8_t *mac = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *x2y2 = new uint8_t[NUM_ECC_DIGITS * 2];
    EccPoint C1;
    uint8_t *p_pvk = new uint8_t[NUM_ECC_DIGITS];

    EccPoint *p_C1;
    uint8_t *p_C3;
    uint8_t *p_C2;
    int C2_len = 0;

    p_C1 = (EccPoint *)(cipher_text + 1);
    p_C3 = cipher_text + 65;
    p_C2 = cipher_text + 97;
    C2_len = cipher_len - 97;

    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        C1.x[i] = p_C1->x[NUM_ECC_DIGITS - i - 1];
        C1.y[i] = p_C1->y[NUM_ECC_DIGITS - i - 1];
        p_pvk[i] = p_priKey[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the privateKey is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pvk[i]);
    }
    printf("\n");

    MES_INFO("extract the C1 from cipher, C1.x is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");
    MES_INFO("extract the C1 from cipher, C1.y is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    ret = EccPoint_is_on_curve(C1);
    if (1 != ret)
    {
        MES_ERROR("C1 is not on curve\n");
        return 0;
    }

    //B2:h=1;S=[h]C1
    if (EccPoint_isZero(&C1))
    {
        MES_ERROR("S is at infinity..\n");
        return 0;
    }

    //B3:[dB]C1 = (x2,y2)
    EccPoint_mult(&point2, &C1, p_pvk, NULL);
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        point2_revrt.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revrt.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("point2.x: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2.x[i]);
    }
    printf("\n");

    MES_INFO("point2.y: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2.y[i]);
    }
#endif
    //B4: t=KDF(x2||y2,klen)
    memcpy(x2y2, point2_revrt.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revrt.y, NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, plain_text, *plain_len);

    if (vli_isZero(plain_text))
    {
        MES_ERROR("r==0,need a different random number\n");
        return 0;
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("kdf out: ");
    for (i = 0; i < *plain_text; ++i)
    {
        printf("%02X", plain_text[i]);
    }
    printf("\n");

    MES_INFO("C2: ");
    for (i = 0; i < C2_len; ++i)
    {
        printf("%02X", p_C2[i]);
    }
    printf("\n");
#endif

    //B5: M' = C2 ^ t
    for (i = 0; i < C2_len; ++i)
    {
        plain_text[i] ^= p_C2[i];
    }
    plain_text[*plain_len] = '\0';

    //B6: check Hash(x2 || M || y2) == C3
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revrt.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, *plain_len);
    sm3_update(&sm3_ctx, point2_revrt.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, mac);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("mac: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", mac[i]);
    }
    printf("\n");

    MES_INFO("cipher->M: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_C3[i]);
    }
    printf("\n");
#endif

    if (0 != memcmp(p_C3, mac, NUM_ECC_DIGITS))
    {
        MES_ERROR("Hash(x2 || M || y2) not equals C3\n");
        return 0;
    }

    FREEARRAY(mac);
    FREEARRAY(x2y2);
    FREEARRAY(p_pvk);
    return 1;
}

void test_sm2_encrypt_decrypt()
{
    //1、设置加解密信息
    const char *plain_text = "Hello my friend";
    unsigned int plain_len = strlen(plain_text);

    MES_INFO("the plain text is: %s\n", plain_text);

    MES_INFO("setting the private key and public key\n");
    //2、设置公私钥
    uint8_t *d1_str = NULL;
    uint8_t *d2_str = NULL;
    EccPoint p_publicKey;
    makeRandom(d1_str);
    makeRandom(d2_str);

    uint8_t *d1_key = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *d2_key = new uint8_t[NUM_ECC_DIGITS];

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the private key d1 is: %s\n", d1_str);
    MES_INFO("the private key d2 is: %s\n", d2_str);
#endif //__SM2_TEST_DEBUG__

    tohex(d1_str, d1_key, NUM_ECC_DIGITS);
    tohex(d2_str, d2_key, NUM_ECC_DIGITS);

    /*************************重点排查区域********************************/

    //P = d1d2G-G
    EccPoint d1d2G;
    EccPoint_mult(&d1d2G, &curve_G, d2_key, NULL);
    EccPoint_mult(&p_publicKey, &d1d2G, d1_key, NULL);

    uint8_t *x1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *y1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *x2 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *y2 = new uint8_t[NUM_ECC_DIGITS];

    vli_set(d1d2G.x, x1);
    vli_set(d1d2G.y, y1);
    vli_set(curve_G.x, x2);
    vli_set(curve_G.y, y2);

    //调用xycz_addc计算d1d2G-G，结果在(x2,y2)
    XYcZ_addC(x1, y1, x2, y2);

    vli_set(x2, p_publicKey.x);
    vli_set(y2, p_publicKey.y);

    /*******************************************************************/

    if (!ecc_valid_public_key(&p_publicKey))
    {
        MES_ERROR("the public key may be invalid.\n");
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the public key.x is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_publicKey.x[i]);
    }
    printf("\n");

    MES_INFO("the public key.y is: ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_publicKey.y[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__
       //P = (d1d2-1)G

    uint8_t one[NUM_ECC_DIGITS] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t *d1d2 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *d1d2_1 = new uint8_t[NUM_ECC_DIGITS];
    vli_modMult(d1d2, d1_key, d2_key, curve_p);
    vli_modSub(d1d2_1, d1d2, one, curve_p);

    // EccPoint_mult(&p_publicKey,&curve_G,d1d2_1,NULL);

    //3、加密过程
    MES_INFO("encrypting..\n");

    //3.1 生成随机数(生成的随机数需要满足 C1 = kG在曲线上，放到加密内部好一点)
    uint8_t *p_random = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *rand_str = nullptr;
    makeRandom(rand_str);
    tohex(rand_str,p_random,NUM_ECC_DIGITS);


#ifdef __SM2_TEST_DEBUG__

    EccPoint C1;
    EccPoint_mult(&C1,&curve_G,p_random,NULL);
    if(!EccPoint_is_on_curve(C1))
    {
        MES_ERROR("the C1 may be invalid, for its not on the curve\n");
    }

    MES_INFO("encrypting random string is :");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_random[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    //3.2 加密
    uint8_t *encdata = new uint8_t[1024]; //密文
    unsigned int encdata_len;             //密文长度
    uint8_t *plaintext = (uint8_t *)(plain_text);

    int ret = sm2_encrypt(encdata, &encdata_len, &p_publicKey,
                          p_random, plaintext, plain_len);

    MES_INFO("sm2_encrypt result:%d,result's len: %d\n", ret, encdata_len);

    MES_INFO("encrypting result: ");
    for (int i = 0; i < encdata_len; ++i)
    {
        printf("%02X", encdata[i]);
        if (1 == (i + 1) % 32)
            printf("\n");
    }
    printf("\n");

    //4、解密过程
    MES_INFO("decrypting..\n");
    uint8_t *p_out = new uint8_t[NUM_ECC_DIGITS];
    unsigned int p_out_len = 0;
    ret = sm2_decrypt_self(
        p_out, &p_out_len,
        encdata, encdata_len,
        d1d2_1 //这里感觉不是传这个值(需要明确:在协同计算中私钥是什么)
    );

    MES_INFO("sm2_decrypt result: %d\n", ret);
    MES_INFO("plaintest is :%s\n", p_out);
}

int main()
{
    test_sm2_encrypt_decrypt();
    return 0;
}