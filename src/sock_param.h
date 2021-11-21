#ifndef HEADER_SOCK_PARAM_H
#define HEADER_SOCK_PARAM_H

#pragma once

#include"common.h"
#include"sm3.h"
#include"ecc.h"
#include<WinSock2.h>

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


#endif //HEADER_SOCK_PARAM_H