/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include<WinSock2.h>
#pragma comment(lib,"ws2_32.lib");


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
    protected:
        int privateKey;
        SOCKET mSocket;
};

class SM2Client : public SM2Socket
{
    public:
        void Init();
        int send(unsigned char*);
        int recv(unsigned char*);
        int connect(const string&ip,int port);
        int disconnect();
        bool isOpen();
        EccPoint CalData_sign();
        EccPoint CalData_decrypt();
        void create_private_key();
        void create_public_key();
};



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


#endif //HEAEDER_SM2_H