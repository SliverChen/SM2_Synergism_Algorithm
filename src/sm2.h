/*
    the header of SM2 algorithms
*/

#ifndef HEADER_SM2_H
#define HEADER_SM2_H

#include"common.h"
#include"ecc.h"
#include"sm3.h"
#include<WinSock2.h>


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
};

class SM2Client : public SM2Socket
{
    public:

        //产生私钥
        void create_private_key();
        
        //产生公钥
        void create_public_key();
        
        //加密
        int Encrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            unsigned char* Message_Decrypted
            );

        //解密
        int Decrypt_SM2(
            unsigned char* Message_Encrypted,
            int length,
            const string &ip,
            int port,
            unsigned char* Message_Decrypted
            );

    private:
        void Init();
        
        int connect(const string&ip,int port);
        
        int disconnect();
        
        int send(unsigned char*);
        
        int recv(unsigned char*);
        
        bool isOpen();
        
        EccPoint CalData_sign();
        
        EccPoint CalData_decrypt(const string& ip,int port);
        
        int sm2_encrypt(
            uint8_t* cipher_text,
            unsigned int *cpiher_len,
            EccPoint* p_publicKey,
            uint8_t p_random[NUM_ECC_DIGITS],
            uint8_t* plain_text,
            unsigned int plain_len
            );

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
        uint8_t* m_priKey;
        uint8_t* m_pubKey_R;
        uint8_t* m_pubKey_S;
        SOCKET mSocket;
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