/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include<WinSock2.h>
#pragma comment(lib,"ws2_32.lib");


#ifdef _cplusplus
extern "C"{
#endif //_cplusplus

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


/*
    SM2客户端实例

    ip:         服务端ip地址
    port:       服务端开放接口
    mSocket:    客户端套接字
    serverAddr: 服务端地址实例
    privateKey: 私钥
*/
typedef struct SM2_Socket{

    string ip;
    int port;
    SOCKET* mSocket;
    sockaddr_in* serverAddr;

}SM2Client;

/*
    SM2 encrypt(normally can imitate the SM2 algorithm)
*/
int Encrypt_SM2(unsigned char* Message_original,int length,unsigned char* Message_Encrypted);


/*
    SM2 Synergism decrypt
*/
int Decrypt_SM2(unsigned char* Message_Encrypted,int length,unsigned char* Message_Decrypted);



#ifdef _cplusplus
}
#endif //_cplusplus

#endif //HEAEDER_SM2_H