#include "sm2Client.h"

SM2Client::SM2Client()
{
    //初始化wsa环境
    WORD sockVersion = MAKEWORD(2, 2);
    if (WSAStartup(sockVersion, &wsaData) != 0)
    {
        MES_ERROR("cannot start wsa, please check socket version\n");
        WSACleanup();
        exit(-1);
    }

    //初始化socket变量
    if ((mSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        MES_ERROR("cannot create the socket,please check your setting\n");
        exit(-1);
    }

    //开辟内存存储私钥和公钥
    m_priKey = new uint8_t[NUM_ECC_DIGITS];
    m_pubKey_x = new uint8_t[NUM_ECC_DIGITS];
    m_pubKey_y = new uint8_t[NUM_ECC_DIGITS];
}

SM2Client::~SM2Client()
{
    //断开连接
    disconnect();

    //释放WSA环境
    WSACleanup();

    //释放私钥和公钥内存
    FREEARRAY(m_priKey);
    FREEARRAY(m_pubKey_x);
    FREEARRAY(m_pubKey_y);
}

void SM2Client::create_private_key()
{
    //1、生成私钥字符串(64位字符串，由数字和小写字母组成)
    uint8_t* priKey_Str = nullptr;
    makeRandom(priKey_Str);

    //2、将字符串转换为uint8_t[NUM_ECC_DIGITS]的形式
    tohex(priKey_Str, m_priKey, NUM_ECC_DIGITS);
}

void SM2Client::create_public_key()
{
    //1、没有私钥时创建私钥(这种判断似乎没有效,因为在构造的时候分配了内存)
    if (m_priKey == nullptr)
        create_private_key();

    //2、基点G在哪,G的阶？在ecc_param.h已给定(curve_G curve_n)

    //3、P1 = d1*G
    EccPoint P1;
    uint8_t *p_pvk = new uint8_t[NUM_ECC_DIGITS];

    //至今也搞不懂为什么要从后面开始取
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        p_pvk[i] = m_priKey[NUM_ECC_DIGITS - i - 1];
    }

    EccPoint_mult(&P1, &curve_G, p_pvk, NULL);

    //4、发送P1到对端
    vector<EccPoint> data;
    data.push_back(P1);
    Send(data);

    //5、接收P = d1*d2G-G
    data = Recv();

    //6、接收后倒回来
    for (int i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        m_pubKey_x[i] = data[0].x[NUM_ECC_DIGITS - i - 1];
        m_pubKey_y[i] = data[0].y[NUM_ECC_DIGITS - i - 1];
    }
}

EccPoint SM2Client::getPublicKey()
{
    EccPoint point;
    vli_set(m_pubKey_x, &point.x);
    vli_set(m_pubKey_y, &point.y);
    return point;
}

int SM2Client::getE(
    char *IDa, int IDLen,
    unsigned char *xa, unsigned char *ya,
    unsigned char *plaintext, unsigned int plainLen,
    unsigned char *e)
{
#define SM3_OUTSIZE 32
    unsigned char Za[64];
    unsigned char *M;

    sm2_get_z((unsigned char *)IDa, strlen(IDa), xa, ya, Za);
    M = (unsigned char *)malloc(plainLen + SM3_OUTSIZE);
    memset(M, 0, plainlen + SM3_OUTSIZE);
    memcpy(M, Za, SM3_OUTSIZE);
    memcpy(M + SM3_OUTSIZE, plaintext, plainLen);
    sm3(M, SM3_OUTSIZE + plainLen, e);

#ifdef __SM2_DEBUG__
    int i = 0;
    MES_INFO("Hash: ");
    for (i = 0; i < 32; ++i)
        printf("%02X", e[i]);
    printf("\n");
#endif //__SM2_DEBUG__

    FREE(M);
    return 1;
}

int SM2Client::get_z(
    unsigned char *IDa, int IDLen,
    unsigned char *xa, unsigned char *ya, unsigned char *Za)
{
    unsigned char Z[256];
    unsigned char *p = Z;
    unsigned int len = 0;

    unsigned char a[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};

    unsigned char b[] = {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};

    unsigned char xG[] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};

    unsigned char yG[] = {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};

    unsigned short idBitLen = IDLen * 8;

    if (IDLen > 32)
        return -1;

    *p = (idBitLen >> 8) & 0xff;
    *(p + 1) = idBitLen & 0xff;
    p += sizeof(idBitLen);
    len += sizeof(idBitLen);

    memcpy(p, IDa, IDLen);
    p += IDLen;
    len += IDLen;

    memcpy(p, a, sizeof(a));
    p += sizeof(a);
    len += sizeof(a);

    memcpy(p, b, sizeof(b));
    p += sizeof(b);
    len += sizeof(b);

    memcpy(p, xG, sizeof(xG));
    p += sizeof(xG);
    len += sizeof(xG);

    memcpy(p, yG, sizeof(yG));
    p += sizeof(yG);
    len += sizeof(yG);

    memcpy(p, xa, 32);
    p += 32;
    len += 32;

    memcpy(p, ya, 32);
    //p += 32;
    len += 32;

    //len = (unsigned int)p - (unsigned int)Z;
    sm3(Z, len, Za);

    return 0;
}

int SM2Client::Encrypt_SM2(
    unsigned char *Message_Encrypted,
    int length,
    unsigned char *Message_original)
{

    /* 数据预处理 */
    unsigned int encdata_len;

    uint8_t randomKey[NUM_ECC_DIGITS];
    EccPoint publicKey;
    vli_set(m_pubKey_x, publicKey.x);
    vli_set(m_pubKey_y, publicKey.y);

    //生成随机数k
    //注意k的生成先获取一串unsigned char字符串，然后再通过tohex的形式转换为可以计算的类型
    unsigned char *randomStr = nullptr;
    makeRandom(randomStr);

    //将随机数转换为十六进制形式的unsigned char数组
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
        MES_ERROR("S is at infinity...\n");
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
            MES_ERROR("the part \"R\" equals 0, need a different random number.\n");
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
    //1、连接到服务端，同时检查连接的有效性
    if (Connect(ip, port) != SUCCESS)
    {
        MES_ERROR("can not finish the decryption.\n");
        return 0;
    }

    //2、转换unsigned char* 为 32位的16进制数组
    unsigned char encData_hex[65535];
    uint8_t p_privateKey[NUM_ECC_DIGITS];
    tohex(Message_Encrypted, encData_hex, length + 2);
    tohex(m_priKey, p_privateKey, NUM_ECC_DIGITS);

    //3、解密的具体过程
    unsigned int p_out_len = 0;
    int ret = sm2_decrypt(
        Message_Decrypted, &p_out_len, encData_hex, length, p_privateKey);

    //4、断开连接
    disconnect();

    //5、释放内存
    FREEARRAY(p_privateKey);
    FREEARRAY(encData_hex);

    return ret;
}

int SM2Client::sm2_decrypt(
                    uint8_t *plain_text, unsigned int *plain_len,
                    uint8_t *cipher_text, unsigned int cipher_len,
                    uint8_t p_privateKey[NUM_ECC_DIGITS])
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

    //B1:C = C1 || C3 || C2  get the C1,C2,C3 from C
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
        MES_ERROR("C1 error,please check the function\n");
        return 0;
    }

    //B2:h=1;S=[h]C1;
    if (EccPoint_isZero(&C1))
    {
        MES_ERROR("S is at infinity...\n");
        return 0;
    }

#ifdef __SM2_DEBUG__
    MES_INFO("p_privateKey: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", p_pvk[i]);
    }

    MES_INFO("cipher->C1.x: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.x[i]);
    }
    printf("\n");

    MES_INFO("cipher->C1.y: ");
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        printf("%02X", C1.y[i]);
    }
    printf("\n");
#endif //__SM2_DEBUG__

    //B2:[dB]C1=(x2,y2)
    //using synergism calculating
    EccPoint point2 = CalData_decrypt(C1);

#ifdef __SM2_DEBUG__
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
#endif //__SM2_DEBUG__

    //B3:t = KDF(x2||y2,klen)
    memcpy(x2y2, point2_revrt.x, NUM_ECC_DIGITS);
    memcpy(x2y2 + NUM_ECC_DIGITS, point2_revrt.y, NUM_ECC_DIGITS);

    *plain_len = C2_len;
    x9_63_kdf_sm3(x2y2, NUM_ECC_DIGITS * 2, plain_text, *plain_len);

    if (vli_isZero(plain_text))
    {
        MES_ERROR("the part \"r\" of the text equals 0");
        printf(", which needs a different random number.\n");
        return 0;
    }

#ifdef __SM2_DEBUG__
    MES_INFO("kdf out: ");
    for (i = 0; i < *plain_len; ++i)
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
#endif // __SM2_DEBUG__

    if (0 != memcmp(p_C3, mac, NUM_ECC_DIGITS))
    {
        MES_ERROR(" hash error \n");
        return 0;
    }

    return 1;
}

EccPoint SM2Client::CalData_decrypt(const EccPoint &C1)
{
    /* 客户端下的协同解密操作 */

    //1、参数传入密文第一部分内容c1

    //2、生成随机数k1,将私钥和随机数转换为32位的16进制数组
    uint8_t *d1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *k1 = new uint8_t[NUM_ECC_DIGITS];
    uint8_t *k1_rand = nullptr;
    makeRandom(k1_rand);

    tohex(k1_rand, k1, NUM_ECC_DIGITS);
    tohex(m_priKey, d1, NUM_ECC_DIGITS);

    //3、计算Q1 = (k1 + d1)C1,并发送Q1给服务端
    EccPoint Q1;
    uint8_t tmp = 0x00;
    uint8_t *k1_add_d1 = new uint8_t[NUM_ECC_DIGITS];
    vli_modAdd(k1_add_d1, k1, d1, curve_n);
    EccPoint_mult(&Q1, &C1, k1_add_d1, NULL);
    for (i = 0; i < NUM_ECC_DIGITS / 2; ++i)
    {
        Q1.x[i] = Q1.x[NUM_ECC_DIGITS - i - 1];
        Q1.y[i] = Q1.y[NUM_ECC_DIGITS - i - 1];
    }

    vector<EccPoint> *decry_client_param1 = new vector<EccPoint>();
    decry_client_param1->push_back(Q1);

    send(decry_client_param1);
    decry_client_param1->clear();
    FREE(decry_client_param1);
    
    //后续客户端不再发送数据，此时可以关掉发送通道
    //让客户端与服务端的连接处于半关闭的状态
    //此时只需要等待服务端最后计算好的数据发过来，连接即可断开
    shutdown(mSocket, SD_SEND);

    //4、接收服务端发送的Q2,Q3
    vector<EccPoint> *decry_client_param2 = recv();

    //5、接收完之后即可断开连接
    disconnect();

    EccPoint Q2 = decry_client_param2->at(0);
    EccPoint Q3 = decry_client_param2->at(1);

    //6、计算(x2,y2)=Q2-k1Q3+(d1-1)C1
    EccPoint x2y2;

    //6.1 计算k1Q3
    uint8_t *k1_mult_Q3 = new uint8_t[NUM_ECC_DIGITS];
    EccPoint k1Q3, k1Q3_revrt;
    EccPoint_mult(&k1Q3, &Q3, k1, NULL);
    for (i = 0; i < NUM_ECC_DIGITS; ++i)
    {
        k1Q3_revrt.x[i] = k1Q3[NUM_ECC_DIGITS - i - 1];
        k1Q3_revrt.y[i] = k1Q3[NUM_ECC_DIGITS - i - 1];
    }

    //6.2 计算Q2-k1Q3
    EccPoint Q2_k1Q3;


    //7、返回P=(x2,y2)
    return x2y2;
}


int SM2Client::Connect(const string &ip, int port)
{
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(ip.c_str());
    server.sin_port = htons(port);
    if (connect(mSocket, (SOCKADDR *)&server, sizeof(server)) == SOCKET_ERROR)
    {
        MES_ERROR("cannot connect to the server,please check the ip and port correctly\n");
        return 0;
    }
    MES_ERROR("successfully connecting with the server\n");
    return 1;
}

int SM2Client::Send(vector<EccPoint> &points,int signal)
{
    MES_INFO("sending data to the server..\n");
    //数据预处理(从EccPoint类型转换为char*类型)
    //同时设计一个首部记录数据的长度
    //中途会涉及到字符串拼接的操作
    //ASCII编码从0-255，因此可以用16进制来表示
    //在传输数据的时候，将数据的16进制格式传过去更安全

    int size = points->size();

    /* 传输数据的格式: 标识+点数量+点数据 */
    string buffer = to_string(signal);
    buffer.append(to_string(size));

    string point_str;
    for (auto point : points)
    {
        //这里将32个用两位表示的十六进制来作为数据传输)
        //总的来说，单个坐标的长度是64个字节
        tostr(point.x, point_str, NUM_ECC_DIGITS);
        buffer.append(point_str);

        tostr(point.y, point_str, NUM_ECC_DIGITS)
            buffer.append(point_str);
    }

#ifdef __SM2_DEBUG__
    MES_INFO("the sending data is: %s\n",buffer);

    //数据传输
    const char *mess = buffer.c_str();
    int ret = send(mSocket, mess, strlen(mess), 0);
    if (ret == SOCKET_ERROR || ret == 0)
    {
        if (mSocket == INVALID_SOCKET)
        {
            MES_ERROR("the client socket is invalid\n");
        }
        MES_ERROR("can not send the message, please check the sockAddr\n");
        return 0;
    }

    MES_INFO("successfully sending data to Server\n");

    //释放内存
    delete mess;

    return 1;
}

vector<EccPoint> SM2Client::Recv()
{
    /*
    *  这里不需要对数据进行提取标识的操作
    *  因为客户端处于主动发送的一方，本身知道目前正在进行哪个步骤，只需获取长度和数据即可
    */
    //1、接收数据
    char data[65535];
    int ret;
    while ((ret = recv(mSocket, data, 65535, 0)) <= 0 && errno == EINTR)
    {
        Sleep(1);
    }

    //1.1 利用接收函数检测连接的有效性
    if (ret <= 0 && errno != EINTR)
    {
        MES_ERROR("the connection has closed,shut down the calculating\n");
        return 0;
    }

    data[ret] = '\0'; //如果能够接收，则recv()返回的是数据的长度
    MES_INFO("receive the data from server,transforming data..\n");

    //2、数据处理(从char[65535]中提取数据并转换为EccPoint类型)
    //数据的结构: 首部+数据
    //需要先提取首部，从首部中获取对应的数据定义和数据长度
    //根据数据定义和数据长度来对数据进行相应的处理

    //2.1 提取数据的首部信息(点的数量)
    int length = atoi(data[0]);

    //2.2 依次提取
    vector<EccPoint> points;
    EccPoint point;

    char *tempData = new char[NUM_ECC_DIGITS * 2];
    uint8_t *data_convrt = new uint8_t[NUM_ECC_DIGITS];
    for (int i = 0; i < length; ++i)
    {
        memcpy(tempData, &data[i * NUM_ECC_DIGITS * 4 + 1], NUM_ECC_DIGITS * 2);

#ifdef __SM2_DEBUG__
        MES_INFO("the No.%d receiving data1: %s\n",i+1,tempData);
#endif //__SM2_DEBUG__

        data_convrt = reinterpret_cast<uint8_t *>(tempData);
        tohex(data_convrt, &point.x, NUM_ECC_DIGITS);


        memcpy(tempData, &data[i * NUM_ECC_DIGITS * 4 + 1 + NUM_ECC_DIGITS * 2], NUM_ECC_DIGITS * 2);

#ifdef __SM2_DEBUG__
        MES_INFO("the No.%d receiving data2: %s\n",i+1,tempData);
#endif //__SM2_DEBUG__

        data_convrt = reinterpret_cast<uint8_t*>(tempData);
        tohex(data_convrt,&point.y,NUM_ECC_DIGITS);
    
        points.push_back(point);
    }

    MES_INFO("successfully transforming data..\n");
    return points;
}

int SM2Client::disconnect()
{
    //断开连接的操作有待思考

    //这个操作需要双方都执行这一步算是断开连接
    if (mSocket != INVALID_SOCKET)
    {
        closesocket(mSocket);
    }

    return 1;
}