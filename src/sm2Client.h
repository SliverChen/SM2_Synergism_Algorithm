#ifndef HEADER_SM2CLIENT_H
#define HEADER_SM2CLIENT_H

#pragma once

#include"sock_param.h"

/*
    @brief SM2客户端类
    用于表示SM2下的客户端
*/
class SM2Client : public SM2Socket
{
    public:

        /*
            @brief 初始化socket环境和socket变量
        */
        SM2Client();

        ~SM2Client();

        /*
            @brief 生成私钥
        */
        void create_private_key();
        
        /*
            @brief 生成公钥
        */
        void create_public_key();

        /*
            @brief 获取已生成的公钥
            @returns EccPoint形式的公钥
        */
        EccPoint getPublicKey();

        /*
            @brief 获取消息的消息摘要e
            @returns 1 if success, 0 otherwise
        */
        int getE(
            char* IDa,int IDLen,
            unsigned char* xa,unsigned char* ya,
            unsigned char* plaintext,unsigned int plainLen,
            unsigned char* e
            );
        
        /*
            @brief 加密的对外接口
            @param Message_Encrypted 加密后的消息
            @param length 消息的长度
            @param Message_original 消息原文
        */
        int Encrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            unsigned char* Message_original
            );

        /*
            @brief 解密的对外接口
            @param Message_Encrypted 加密后的消息
            @param length 消息长度
            @param ip 服务端的ip地址
            @param port 服务端开放连接的端口号
            @param Message_Decrypted 解密后的消息
            @returns 1 if success, 0 otherwise
        */
        int Decrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            const string &ip,
            int port,
            unsigned char* Message_Decrypted
            );

    private:
        
        /*
            @brief 与服务端建立连接
            @param ip 服务端的ip地址
            @param port 服务端开放连接的端口号
            @returns 1 if connecting successfully,0 otherwise
        */
        int Connect(const string&ip,int port);
        

        /*
            @brief 断开连接
            @returns 1 if succeed to disconnect, 0 otherwise
        */
        int disconnect();

        /*
            @brief ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
        */
        int get_z(
            unsigned char* IDa,int IDLen,
            unsigned char* xa,unsigned char* ya,
            unsigned char* Za
        );
        
        //为了让发送函数更具通用性，将传递的数据以vector的形式传进去
        //在函数内部同时实现对EccPoint数据类型的转换

        /*
            @brief 协同计算下的发送函数
            @param points 将要发送的一组EccPoint类型数据
            @param 发送的数据的标识(标识数据存在的过程:生成公钥,签名,解密)
            @returns 1 if send successfully, 0 otherwise
        */
        int Send(vector<EccPoint>& points,int signal);
        
        //为了让接收函数更具通用性，将接收的数据以vector的形式存储返回
        //在函数内部同时实现对接收数据的数据类型转换

        /*
            @brief 协同计算下的接收函数
            @returns 接收到的经过处理后的一组EccPoint类型数据
        */
        vector<EccPoint> Recv();
        

        /*
            @brief 检测是否已连接
            @returns true if connected, false otherwise
        */
        bool isConnected();
        

        /*
            @brief 签名过程中的协同计算
            @returns 签名(r,s)
        */
        EccPoint CalData_sign();
        

        /*
            @brief 解密过程中的协同计算
            @param C1 根据密文的格式C=C1||C3||C2提取的密文第一部分内容
            @returns 协同计算的结果(x2,y2)
        */
        EccPoint CalData_decrypt(const EccPoint& C1);
        

        /*
            @brief 加密过程
            @param cipher_text 返回的密文内容
            @param cipher_len  返回的密文长度
            @param p_publicKey 经过转换之后的公钥
            @param p_random    随机数
            @param plain_text  传入的原文内容
            @param plain_len   传入的原文长度
            @returns 1 if encrypt successfully, 0 otherwise
        */
        int sm2_encrypt(
            uint8_t* cipher_text,
            unsigned int *cpiher_len,
            EccPoint* p_publicKey,
            uint8_t p_random[NUM_ECC_DIGITS],
            uint8_t* plain_text,
            unsigned int plain_len
            );


        /*
            @brief 解密过程
            @param plain_text   返回的原文内容
            @param plain_len    返回的原文长度
            @param cipher_text  传入的密文内容
            @param cipher_len   传入的密文长度
            @param p_privateKey 经过转换之后的私钥
            @param ip           服务端的ip地址
            @param port         服务端的端口号
            @returns 1 if decrypt successfully,0 otherwise
        */
        int sm2_decrypt(
            uint8_t* plain_text,
            unsigned int* plain_len,
            uint8_t* cipher_text,
            unsigned int cipher_len,
            uint8_t p_privateKey[NUM_ECC_DIGITS],
            const string& ip,
            int port
        );

    private:
        uint8_t* m_priKey;            //私钥
        uint8_t* m_pubKey_x;          //公钥在椭圆曲线下的x
        uint8_t* m_pubKey_y;          //公钥在椭圆曲线下的y
        SOCKET mSocket;               //客户端socket变量
        sockaddr server;              //服务端的地址信息
};

#endif //HEADER_SM2CLIENT_H