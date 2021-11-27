/*
*   公共部分(每个头文件都会包含)
*/

#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H

//标准化输出
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#include <unistd.h>
#endif //_WIN32

#include <stdlib.h>
#include <stdio.h>
#include <iomanip>

//随机数生成(这个只需要出现在新的C++代码中)
#include <openssl/bn.h>
#pragma comment(lib, "libapps.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libssl_static.lib")
#pragma comment(lib, "openssl.lib")

//字符串的处理
#include <cstring>
using std::string;

//规范化调试语句
typedef struct tm *tm_t;
static time_t curtime;
tm_t timenow;

#define MES_INFO(...)                                  \
    time(&curtime);                                    \
    timenow = localtime(&curtime);                     \
    printf("[%02d:%02d:%02d Info]:", timenow->tm_hour, \
           timenow->tm_min, timenow->tm_sec);          \
    printf(__VA_ARGS__)

#define MES_ERROR(...)                                  \
    time(&curtime);                                     \
    timenow = localtime(&curtime);                      \
    printf("[%02d:%02d:%02d Error]:", timenow->tm_hour, \
           timenow->tm_min, timenow->tm_sec);           \
    printf(__VA_ARGS__)

//通用公式计算(主要用于后续对SM2的拓展，目前用32位即可)
#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

//SM2的数据长度
#define NUM_ECC_DIGITS 32

//内存清理
#define FREE(X) \
    delete X;   \
    X = nullptr;
#define FREEARRAY(X) \
    delete[] X;      \
    X = nullptr;

#endif //HEADER_COMMON_H