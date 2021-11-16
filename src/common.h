#ifndef HEADER_COMMON_H
#define HEADER_COMMON_H
#pragma once

//标准输入输出流
#include<iostream>

//基础数学库
#include<cmath>

//字符串标准库
#include<cstring>

//多线程相关
#include<mutex>
#include<thread>
#include<stdint.h>

//标准化输出
#include<Windows.h>
#include<cstdlib>
#include<iomanip>

using std::string;
using std::cout;

static SYSTEMTIME systemTime;
#define MES_INFO GetLocalTime(&systemTime); \
    cout<<"["<< \
    systemTime.wHour<<":"<<systemTime.wMinute<<":"<<systemTime.wSecond \
    <<" Info]:"

#define MES_ERROR GetLocalTime(&systemTime); \
    cout<<"["<< \
    systemTime.wHour<<":"<<systemTime.wMinute<<":"systemTime.wSecond \
    <<" Error]:"


//内存相关
#define FREE(x) delete x;x=nullptr;
#define FREEARRAY(x) delete[] x;x=nullptr;

//通用公式计算(主要用于后续拓展到512bit的SM2)
#define CONCAT1(a,b) a##b
#define CONCAT(a,b) CONCAT1(a,b)

//256bit的SM2
#define NUM_ECC_DIGITS 32

//others
typedef unsigned int unit;

#endif //HEADER_COMMON_H