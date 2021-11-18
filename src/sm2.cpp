#include "sm2.h"
#include <openssl/rand.h>

#pragma comment(lib, "liapps.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libssl_static.lib")
#pragma comment(lib, "openssl.lib")

void SM2Client::create_private_key()
{
    //私钥是什么形式？
    //在我的认知里它是一个属于[1,n-1]的随机数
    //但是随机数的表达形式是怎么样的呢？

    //生成私钥(64位字符串，由数字和小写字母组成)

    //检验合法性（不能为0）
}

void SM2Client::create_public_key()
{
    //1、没有私钥时调用create_private_key() (需要一个验证随机数是否合法的函数)

    //2、基点G在哪？在ecc_param.h已给定。 G的阶是多少？

    //3、发送P1 = d1*G

    //4、接收P = d1*d2G-G

    //公钥为P
}

int SM2Client::Encrypt_SM2(
    unsigned char *Message_Encrypted,
    int length,
    unsigned char *Message_original)
{

    /* 数据预处理 */
    unsigned int encdata_len;

    uint8_t randomKey[NUM_ECC_DIGITS];
    uint8_t privateKey[NUM_ECC_DIGITS];
    EccPoint publicKey;

    //生成随机数k
    //注意k的生成先获取一串unsigned char字符串，然后再通过tohex的形式转换为可以计算的类型
    unsigned char randomStr[2 * NUM_ECC_DIGITS];
    int ret = RAND_bytes(randomStr, 2 * NUM_ECC_DIGITS);
    if (ret != 1)
    {
        MES_ERROR << "can not create random string,please check the grammar\n";
        exit(-1);
    }

    //将所有参与计算的数据转换无符号字符串为32位的16进制数组
    tohex(m_priKey, privateKey, NUM_ECC_DIGITS);
    tohex(m_pubKey_R, publicKey.x, NUM_ECC_DIGITS);
    tohex(m_pubKey_S, publicKey.y, NUM_ECC_DIGITS);
    tohex(randomStr, randomKey, NUM_ECC_DIGITS);

    /* 正式加密 */
    int ret = sm2_encrypt(
        Message_Encrypted,
        &encdata_len,
        &publicKey,
        randomKey,
        Message_original,
        length);

    for (int i = 0; i < encdata_len; ++i)
    {
        Message_Encrypted[i] = Message_Encrypted[i + 1];
    }

    return ret;
}

int SM2Client::sm2_encrypt(
    uint8_t *cipher_text, unsigned int *cpiher_len, EccPoint *p_publicKey,
    uint8_t p_random[NUM_ECC_DIGITS], uint8_t *plain_text, unsigned int plain_len)
{
    int i = 0;
    uint8_t PC = 0x04;
    uint8_t tmp = 0x00;
    uint8_t k[NUM_ECC_DIGITS];
    EccPoint C1, Pb, point2, point2_revert;
    uint8_t x2y2[NUM_ECC_DIGITS * 2];
    uint8_t C2[65535] = {0};
    uint8_t C3[NUM_ECC_DIGITS];
    sm3_context sm3_ctx;

    //A1: generate random number k
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
        k[i] = p_random[NUM_ECC_DIGITS - i - 1];

    //A2: C1 = [k]G
    EccPoint_mult(&C1, &curve_G, k, NULL);
    for (i = 0; i < NUM_ECC_DIGITS / 2; ++i)
    {
        tmp = C1.x[i];
        C1.x[i] = C1.x[NUM_ECC_DIGITS - i - 1];
        C1.x[NUM_ECC_DIGITS - i - 1] = tmp;

        tmp = C1.y[i];
        C1.y[i] = C1.y[NUM_ECC_DIGITS - i - 1];
        C1.y[NUM_ECC_DIGITS - i - 1] = tmp;
    }

    //A3:h=1;S=[h]Pb
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        Pb.x[i] = p_publicKey->x[NUM_ECC_DIGITS - i - 1];
        Pb.y[i] = p_publicKey->y[NUM_ECC_DIGITS - i - 1];
    }
    if (EccPoint_isZero(&Pb))
    {
        MES_ERROR << "S is at infinity...\n";
        return 0;
    }

    //A4: [k]Pb = (x2,y2)
    EccPoint_mult(&point2, &Pb, k, NULL);
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        point2_revert.x[i] = point2.x[NUM_ECC_DIGITS - i - 1];
        point2_revert.y[i] = point2.y[NUM_ECC_DIGITS - i - 1];
    }

    //A5: t = KED(x2 || y2,klen)
    memcpy(x2y2, point2_revert.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revert.y, NUM_ECC_DIGITS);

    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, C2, plain_text, plain_len);
    if (vli_isZero(C2))
    {
        if (vli_isZero(p_publicKey->x))
        {
            MES_ERROR << "the part \"R\" equals 0, need a different random number.\n";
        }
        return 0;
    }

    //A6: C2 = M^t;
    for (i = 0; i < plain_len; ++i)
    {
        C2[i] ^= plain_text[i];
    }

    //A7: C3 = Hash(x2,M,y2)
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revert.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, plain_len);
    sm3_update(&sm3_ctx, point2_revert.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, C3);

    //A8: C=C1||C3||C2
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

int SM2Client::Decrypt_SM2(
    unsigned char *Message_Encrypted, int length,
    const string &ip, int port, unsigned char *Message_Decrypted)
{
    //convert message and privateKey into hex type(for calculating)
    unsigned char encData_hex[65535];
    uint8_t p_privateKey[NUM_ECC_DIGITS];
    tohex(Message_Encrypted, encData_hex, length + 2);
    tohex(m_priKey, p_privateKey, NUM_ECC_DIGITS);

    //specific decrpting
    unsigned int p_out_len = 0;
    int ret = sm2_decrypt(
        Message_Decrypted, &p_out_len, encData_hex, length, p_privateKey);
    return ret;
}

int SM2Client : sm2_decrypt(
                    uint8_t *plain_text, unsigned int *plain_len,
                    uint8_t *cipher_text, unsigned int cipher_len,
                    uint8_t p_privateKey[NUM_ECC_DIGITS],
                    const string &ip, int port)
{
    int i = 0, ret = 0;
    sm3_context sm3_ctx;
    EccPoint point2;
    EccPoint point2_revrt;
    uint8_t mac[NUM_ECC_DIGITS];
    uint8_t x2y2[NUM_ECC_DIGITS * 2];
    EccPoint C1, S;
    uint8_t p_pvk[NUM_ECC_DIGITS];

    EccPoint *p_C1;
    uint8_t *p_C3;
    uint8_t *p_C2;
    int C2_len = 0;

    //B1:C = C1 || C3 || C2  get the C1 from C
    p_C1 = (EccPoint *)(cipher_text + 1);
    p_C3 = cipher_text + 65;
    p_C2 = cipher_text + 97;
    C2_len = cipher_len - 97;

    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        C1.x[i] = p_C1->x[NUM_ECC_DIGITS - i - 1];
        C1.y[i] = p_C1->y[NUM_ECC_DIGITS - i - 1];
        p_pvk[i] = p_privateKey[NUM_ECC_DIGITS - i - 1];
    }

    ret = EccPoint_is_on_curve(C1);
    if (1 != ret)
    {
        MES_ERROR << "C1 error,please check the function\n";
        return 0;
    }

    //B2:h=1;S=[h]C1;
    if (EccPoint_isZero(&C1))
    {
        MES_ERROR << "S is at infinity...\n";
        return 0;
    }

#ifdef __SM2_DEBUG__
    MES_INFO << "p_privateKey: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pvk[i]);
    }
    printf("\n");

    MES_INFO << "cipher->C1.x: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");

    MES_INFO << "cipher->C1.y: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");
#endif //__SM2_DEBUG__

    //B2:[dB]C1=(x2,y2)
    //using synergism calculating
    CalData_decrypt(ip, port);

#ifdef __SM2_DEBUG__
    MES_INFO << "point2.x: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2.x[i]);
    }
    printf("\n");

    MES_INFO << "point2.y: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", point2.y[i]);
    }
    printf("\n");
#endif //__SM2_DEBUG__

    //B3:t = KDF(x2||y2,klen)
    memcpy(x2y2, point2_revrt.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revrt.y, NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, plain_text, *plain_len);

    if (vli_isZero(plain_text))
    {
        MES_ERROR << "the part \"r\" of the text equals 0"
                  << ", which needs a different random number.\n";
        return 0;
    }

#ifdef __SM2_DEBUG__
    MES_INFO << "kdf out: ";
    for (i = 0; i < *plain_len; ++i)
    {
        printf("%02X", plain_text[i]);
    }
    printf("\n");

    MES_INFO << "C2: ";
    for (i = 0; i < C2_len; ++i)
    {
        printf("%02X", p_C2[i]);
    }
    printf("\n");
#endif //__SM2_DEBUG__

    //B4: M' = C2 ^ t
    for (i = 0; i < C2_len; ++i)
    {
        plain_text[i] ^= p_C2[i];
    }
    plain_text[*plain_len] = '\0';

    //B5: check if Hash(x2 || M || y2) == C3
    sm3_starts(&sm3_ctx);
    sm3_update(&sm3_ctx, point2_revrt.x, NUM_ECC_DIGITS);
    sm3_update(&sm3_ctx, plain_text, *plain_len);
    sm3_update(&sm3_ctx, point2_revrt.y, NUM_ECC_DIGITS);
    sm3_finish(&sm3_ctx, mac);

#ifdef __SM2_DEBUG__
    MES_INFO << "mac: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", mac[i]);
    }

    printf("\n");

    MES_INFO << "cipher->M: ";
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_C3[i]);
    }

    printf("\n");
#endif // __SM2_DEBUG__

    if (0 != memcmp(p_C3, mac, NUM_ECC_DIGITS))
    {
        MES_ERROR << " hash error \n";
        return 0;
    }

    return 1;
}

EccPoint SM2Client::CalData_decrypt()
{
    //1、参数传入密文第一部分内容c1
}