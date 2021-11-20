/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include"sm3.h"
#include<WinSock2.h>


/*
    define to enable SM2 debug function
*/
#define __SM2_DEBUG__


/*
    Optimization settings:
    If enabled, this will cause a specific function 
    to be used multiplication function.
    Improves speed by about 8%
*/
#define __ECC_SQUARE_FUNC 1


/*
    Inline assembly options
    (no usage for now)
*/
#define ecc_asm_none 0
#ifndef ECC_ASM
    #define ECC_ASM ec_asm_none
#endif //ECC_ASM


//WSA版本
static WSADATA wsaData;

class SM2Socket
{
    public:
        virtual void Init() = 0;
        virtual int send(unsigned char*) = 0;
        virtual int recv(unsigned char*) = 0;
};

class SM2Client : public SM2Socket
{
    public:

        //构造时初始化WSA环境和Socket变量
        SM2Client();

        ~SM2Client();

        //产生私钥
        void create_private_key();
        
        //产生公钥
        void create_public_key();

        //获取公钥
        uint8_t* getPublicKey();

        //获取消息的消息摘要
        int getE(
            char* IDa,int IDLen,
            unsigned char* xa,unsigned char* ya,
            unsigned char* plaintext,unsigned int plainLen,
            unsigned char* e
            );
        
        //加密
        int Encrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            unsigned char* Message_Decrypted
            );

        //解密
        int Decrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            const string &ip,
            int port,
            unsigned char* Message_Decrypted
            );

    private:
        void Init();
        
        int Connect(const string&ip,int port);
        
        int disconnect();

        //ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
        int get_z(
            unsigned char* IDa,int IDLen,
            unsigned char* xa,unsigned char* ya,
            unsigned char* Za
        );
        
        //为了让发送函数更具通用性，将传递的数据以vector的形式传进去
        //在函数内部同时实现对EccPoint数据类型的转换
        int Send(vector<EccPoint>&);
        
        //为了让接收函数更具通用性，将接收的数据以vector的形式存储返回
        //在函数内部同时实现对接受数据的数据类型转换
        vector<EccPoint> Recv();
        
        bool isConnected();
        
        EccPoint CalData_sign();
        
        EccPoint CalData_decrypt(const EccPoint& C1);
        
        int sm2_encrypt(
            uint8_t* cipher_text,
            unsigned int *cpiher_len,
            EccPoint* p_publicKey,
            uint8_t p_random[NUM_ECC_DIGITS],
            uint8_t* plain_text,
            unsigned int plain_len
            );

        int sm2_decrypt(
            uint8_t* plain_text,
            unsigned int* plain_len,
            uint8_t* cipher_text,
            unsigned int cipher_len,
            uint8_t p_privateKey[NUM_ECC_DIGITS],
            const string& ip,
            int port
        );

        /*
            @brief 生成[1,n-1]范围内的十六进制随机数
            @param randStr 接收生成的无符号字符串类型随机数
        */
        void makeRandom(uint8_t*& randStr);

    private:
        uint8_t* m_priKey;
        uint8_t* m_pubKey_R;
        uint8_t* m_pubKey_S;
        SOCKET mSocket;
        sockaddr server;
};



#endif //HEAEDER_SM2_H