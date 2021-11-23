#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H
#pragma once

//基础数学库
#include<math.h>

//字符串标准库
#include<string>
#include<string.h>

//标准化输出
#include<Windows.h>
#include<stdlib.h>
#include<stdio.h>
#include<iomanip>

//随机数生成
#include<openssl/bn.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "libapps.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libssl_static.lib")
#pragma comment(lib, "openssl.lib")


SYSTEMTIME systemTime;
#define MES_INFO(...) GetLocalTime(&systemTime); \
    printf("[%02d:%02d:%02d Info]:",systemTime.wHour,\
        systemTime.wMinute,systemTime.wSecond); \
    printf(__VA_ARGS__)

#define MES_ERROR(...) GetLocalTime(&systemTime);\
    printf("[%02d:%02d:%02d Error]:",systemTime.wHour,\
        systemTime.wMinute,systemTime.wSecond); \
    printf(__VA_ARGS__)

//通用公式计算(主要用于后续对SM2的拓展，目前用32位即可)
#define CONCAT1(a,b) a##b
#define CONCAT(a,b) CONCAT1(a,b)

//SM2的数据长度
#define NUM_ECC_DIGITS 32

//函数是否成功调用的标识符
#define SUCCESS 1
#define BAD 0


#endif //HEADER_COMMON_H