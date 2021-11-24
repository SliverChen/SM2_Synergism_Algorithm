/*
*   the header of sock parameters
*   this header include some 
*/

#ifndef HEADER_SOCK_PARAM_H
#define HEADER_SOCK_PARAM_H

#pragma once

#include"common.h"
#include"sm3.h"
#include"ecc.h"
#include<vector>

using std::vector;

//多线程相关
#include<mutex>
#include<thread>
#include<stdint.h>

//WSA版本
static WSADATA wsaData;

/*
    @brief SM2 Socket通用类
    用于定义客户端与服务端的基类
*/
class SM2Socket
{
    public:
        virtual void create_private_key() = 0;
        virtual EccPoint getPublicKey() = 0;
};

//用于标识服务端接收到的数据信息(判定用于处理什么过程)
//将出现在客户端进行发送时对数据添加首部
//以及服务端接收并解析数据首部时需要使用


/*生成公钥时客户端发送的P1分量*/
constexpr auto PUBLICKEY_P1 = 0;

/* 解密时客户端发送的Q1分量 */
constexpr auto DECRYPT_Q1 = 1;

/* 签名时客户端发送的P1分量*/
constexpr auto SIGN_P1 = 2;

//内存相关
#define FREE(x) delete x;x=nullptr;
#define FREEARRAY(x) delete[] x;x=nullptr;


#endif //HEADER_SOCK_PARAM_H