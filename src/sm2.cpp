#include "sm2.h"
#include<openssl/rand.h>

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

EccPoint SM2Client::CalData_decrypt()
{
    //1、参数传入密文第一部分内容c1
}