/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include<WinSock2.h>
#pragma comment(lib,"ws2_32.lib");


#ifdef __cplusplus
extern "C"{
#endif //__cplusplus

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

/*
    SM2客户端实例

    ip:         服务端ip地址
    port:       服务端开放接口
    mSocket:    客户端套接字
    serverAddr: 服务端地址实例
    privateKey: 私钥
*/
typedef struct SM2_Socket{
    SOCKET* mSocket;          //the client socket
    sockaddr_in* serverAddr;  //the server socket information

    private:
        int privateKey;       //the number rand in [1,n-1]

}SM2Client;


//initialize the socket environment
int Init_Env();

//free the socket environment
int Free_Env();

//initialize the client socket
int Init_Client(SM2Client* mClient);

//free the client socket
int Free_Client(SM2Client* mClient);

/*
    make client connect with the server
    @param mClient the struct of the client
    @param ip_server the ip of server
    @param port_server the port of server
    @return 1 if connection is success, 0 otherwise
*/
int Connect_Server_Client(SM2Client* mClient,const string& ip_Server,int port_Server);


/*
    make client disconnect with the server
    @param mClient the struct of the client
*/
int Disconnect_Server_Client(SM2Client* mClient);

/*
    Send message to Client
*/

/*
    SM2 encrypt(normally can imitate the SM2 algorithm)
*/
int Encrypt_SM2(unsigned char* Message_original,int length,unsigned char* Message_Encrypted);


/*
    SM2 Synergism decrypt
*/
int Decrypt_SM2(unsigned char* Message_Encrypted,int length,unsigned char* Message_Decrypted);



#ifdef __cplusplus
}
#endif //__cplusplus

#endif //HEAEDER_SM2_H