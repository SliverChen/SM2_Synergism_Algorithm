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

    目前进度(11.26 9:11):
        由于使用mac环境，导致原本代码上的windows.h无法使用
        为了能够让代码具有兼容性，寻找另一个能够替代windows.h下SYSTEMTIME的标准库，同时能够在win和mac环境下使用

    目前进度(11.26 16:45):
        由于mac环境的限制，导致gcc的编译也出现了问题
        主要表现为在sm3.c的文件下使用了fopen_s的函数，该函数无法在C99标准下使用
        （至少它的报错信息是提示implicit declaration of function 'fopen_s' is invalid in C99
        [-Werror,-Wimplicit-function-declaration]）
        至于是编译环境的问题还是真的不能在C99标准下使用还需要深入研究

        出现上面的问题的前置问题是主函数定位不到头文件的实现文件导致出现
        undefined symbols for architecture arm64的错误

        需要单独编译一遍所有有实现文件的头文件，生成.o文件
        然后再使用ar将所有的.o文件合并成.a文件供主函数识别
*/

#include "./src/sm2.h"

int sm2_encrypt(uint8_t *cipher_text, unsigned int *cipher_len, EccPoint *p_publicKey, uint8_t *plain_text, unsigned int plain_len)
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
    uint8_t *C2 = new uint8_t[1024];
    uint8_t *C3 = new uint8_t[NUM_ECC_DIGITS];
    sm3_context sm3_ctx;

    //A1:generate random number k;
    uint8_t* randStr = nullptr;
    makeRandom(randStr);
    tohex(randStr, k, NUM_ECC_DIGITS);
    //FREE(randStr);  
    //error 提前释放randStr的内存会报crtlsvalidheappointer(block)的错误
    //出现这个错误的原因主要在堆内存的指针释放的问题

    //这里不需要反转
    //因为参考算法传进来的随机数本身是反序的
    //我们这里生成的随机数是正序的

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
    MES_INFO("C1.x is(before revert): ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");

    MES_INFO("C1.y is(before revert): ");
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

    //这里反转是为了后续将其放到密文当中
    //没有任何计算的意义
    //需要注意的是这里只需要循环一半，否则会与原本保持不变
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

    //这里不需要反转
    //因为参考算法的测试代码传进来的公钥本身是反序的
    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        //Pb.x[i] = p_publicKey->x[NUM_ECC_DIGITS - i - 1];
        //Pb.y[i] = p_publicKey->y[NUM_ECC_DIGITS - i - 1];

        Pb.x[i] = p_publicKey->x[i];
        Pb.y[i] = p_publicKey->y[i];
    }
    if (EccPoint_isZero(&Pb))
    {
        MES_ERROR("S at infinity...\n");
        return 0;
    }

    //A4:[k]Pb = (x2, y2);
    //用两个正序计算的结果显然是正序的
    EccPoint_mult(&point2, &Pb, k, NULL);

    //这里反转是为了后续对C2的计算
    //涉及到了kdf函数的使用
    for (i = 0; i < NUM_ECC_DIGITS; i++)
    {
        point2_revert.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revert.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("point2.x is(after revert): ");
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2_revert.x[i]);
    }
    printf("\n");
    MES_INFO("point2.y is(after revert): ");
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
    MES_INFO("C2 is: ");
    for (int i = 0; i < plain_len; ++i)
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
    MES_INFO("C3 is : ");
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


    //这里只需要对提取出来的C1进行反转
    //私钥不需要变化，因为计算出来的私钥是正序的
    //与参考算法的测试代码不同，传进来之前私钥是反序的

    //但是C1和私钥是否需要反序来参与C2的计算？
    //尝试一下
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        C1.x[i] = p_C1->x[NUM_ECC_DIGITS - i - 1];
        C1.y[i] = p_C1->y[NUM_ECC_DIGITS - i - 1];

        //p_pvk[i] = p_priKey[NUM_ECC_DIGITS - i - 1];
        p_pvk[i] = p_priKey[i];  
    }

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the privateKey is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pvk[i]);
    }
    printf("\n");

    MES_INFO("C1.x is(after revert): ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");
    MES_INFO("C1.y is(after revert): ");
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

        /*******************test*************************/
        //return 0;
    }

    //B2:h=1;S=[h]C1
    if (EccPoint_isZero(&C1))
    {
        MES_ERROR("S is at infinity..\n");
        return 0;
    }

    //B3:[dB]C1 = (x2,y2)
    EccPoint_mult(&point2, &C1, p_pvk, NULL);

    //这里为什么要反转*******************************************这里有问题
    //本身放在密文的C2在计算的时候就是反序的
    //如果提取出来再反转就变成了A4计算步骤的值
    //A4的值是不参与计算的，这一点需要注意
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        //point2_revrt.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        //point2_revrt.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];

        point2_revrt.x[i] = point2.x[i];
        point2_revrt.y[i] = point2.y[i];
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
    printf("\n");
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
    for (i = 0; i < (int) * plain_len; ++i)
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
    MES_INFO("Hash value: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", mac[i]);
    }
    printf("\n");

    MES_INFO("cipher->M:  ");
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
    int i;

    //1、设置测试的消息字符串
    const char* plain_text = "my name is Van";
    unsigned int plain_len = strlen(plain_text);

    MES_INFO("the plain text is: %s, which lengt is %d\n", plain_text,plain_len);


    //2、生成私钥（这里的计算可能有些问题: d1d2-1）
    
    uint8_t* d1_str = nullptr;
    uint8_t* d2_str = nullptr;
    EccPoint p_pubKey{};
    
    makeRandom(d1_str);
    makeRandom(d2_str);

    uint8_t* d1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t* d2 = new uint8_t[NUM_ECC_DIGITS];

    tohex(d1_str, d1, NUM_ECC_DIGITS);
    tohex(d2_str, d2, NUM_ECC_DIGITS);

    uint8_t one[NUM_ECC_DIGITS] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t* d1d2 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t* p_priKey = new uint8_t[NUM_ECC_DIGITS];
    vli_modMult(d1d2, d1, d2, curve_p);
    vli_modSub(p_priKey, d1d2, one, curve_p);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the prikey d1 is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", d1[i]);
    }
    printf("\n");

    MES_INFO("the prikey d2 is : ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", d2[i]);
    }
    printf("\n");
    
    MES_INFO("the prikey is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_priKey[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    //3、计算公钥（这里的计算没有问题: d1d2G - G）
    EccPoint d2G;
    EccPoint d1d2G;
    EccPoint_mult(&d2G, &curve_G, d2, NULL);
    EccPoint_mult(&d1d2G, &d2G, d1, NULL);

    uint8_t* x1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t* y1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t* x2 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t* y2 = new uint8_t[NUM_ECC_DIGITS];

    vli_set(x1,d1d2G.x);
    vli_set(y1,d1d2G.y);
    vli_set(x2,curve_G.x);
    vli_set(y2,curve_G.y);

    //call xycz_addc to calculate d1d2G-G
    //the result is in the (x1,y1)
    XYcZ_addC(x1, y1, x2, y2);

    vli_set(p_pubKey.x,x1);
    vli_set(p_pubKey.y,y1);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("the public key.x is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pubKey.x[i]);
    }
    printf("\n");

    MES_INFO("the public key.y is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pubKey.y[i]);
    }
    printf("\n");
#endif //__SM2_TEST_DEBUG__

    MES_INFO("check the validation of the public key: ");
    if (ecc_valid_public_key(&p_pubKey))
    {
        printf("good\n");
    }
    else
    {
        printf("bad, please check the calculation again\n");
    }

    FREEARRAY(x1); FREEARRAY(y1);
    FREEARRAY(x2); FREEARRAY(y2);


    //这里需要检验公钥和私钥的有效性
    //检验：(d1d2-1)G 是否等于 d1d2G - G
    //在正常情况下，公钥pub和私钥pri之间的关系为：pub = [pri]G
    //二者通过一个椭圆曲线的点进行关联
    //私钥在当前算法的形式为 d1d2-1
    //公钥在当前算法的形式为 (d1d2-1)G

    EccPoint d1d2_1G;
    EccPoint_mult(&d1d2_1G, &curve_G, p_priKey, NULL);

#ifdef __SM2_TEST_DEBUG__
    MES_INFO("d1d2_1G.x is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", d1d2_1G.x[i]);
    }
    printf("\n");

    MES_INFO("d1d2_1G.y is: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", d1d2_1G.y[i]);
    }
    printf("\n");

#endif //__SM2_TEST_DEBUG__


    if (vli_cmp(d1d2_1G.x, p_pubKey.x) == 0 && vli_cmp(d1d2_1G.y, p_pubKey.y) == 0)
    {
        MES_INFO("d1d2_1G equals public key, which it is valid.\n");
    }
    else
    {
        MES_ERROR("d1d2_1G not equals public key, which it is invalid.\n");
    }


    //4、加密过程
    printf("\n");
    MES_INFO("*************encrypting************\n");
    uint8_t* encdata = new uint8_t[1024];
    uint8_t* plaintext = (uint8_t*)const_cast<char*>(plain_text);
    unsigned int encdata_len;

    int ret = sm2_encrypt(encdata, &encdata_len, &p_pubKey,
        plaintext, plain_len);

    MES_INFO("sm2_encrypt result:%d, result's len:%d \n", ret, encdata_len);

    MES_INFO("encrypting result: ");
    for (i = 0; i < encdata_len; ++i)
    {
        printf("%02X", encdata[i]);
        if (1 == (i + 1) % 32)
            printf("\n");
    }
    printf("\n\n");
   
    //5、解密过程
    MES_INFO("*********************decrypting***************\n");
    uint8_t* p_out = new uint8_t[1024];
    unsigned int p_out_len = 0;
    ret = sm2_decrypt_self(
        p_out, &p_out_len,
        encdata, encdata_len,
        p_priKey
    );

    MES_INFO("sm2_decrypt result: %d\n", ret);
    MES_INFO("plain text is : %s\n", p_out);
}

int main()
{
    test_sm2_encrypt_decrypt();

    return 0;
}