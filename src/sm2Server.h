#ifndef HEADER_SM2SERVER_H
#define HEADER_SM2SERVER_H

#pragma once

#include"sock_param.h"

/*
*	@brief SM2 服务端类
*	用于协助客户端计算公钥,签名和解密
*/
class SM2Server : public SM2Socket
{
public:
	/*
	*	@brief 初始化wsa环境和socket变量
	*	@param port 开放的端口号
	*/
	SM2Server(int port);

	/*
	*	@brief 清理环境设置，释放socket
	*/
	~SM2Server();

	/*
	*	@brief 生成私钥
	*/
	void create_private_key();

	/*
	*	@brief 	获取第i个客户端下的公钥
	*	@returns 公钥在椭圆曲线上的点
	*/
	EccPoint getPublicKey();


	void listenClient();

private:
	/*
	*	@brief 协助客户端签名
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_sign(vector<EccPoint>& points);

	/*
	*	@brief 协助客户端解密
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_decrypt(vector<EccPoint>& points);

	/*
	*	@brief 与客户端合作生成公钥
	*	@param point 客户端传来的中间变量
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_createPubKey(vector<EccPoint>& points);


	/*
	*	@brief 断开连接
	*	@returns 1 if success, 0 otherwise
	*/
	int disconnect();

	/*
	*	@brief 发送数据到对端
	*	@param points: 将要发送的一组EccPoint类型的数据 
	*	@returns 1 if success, 0 otherwise
	*/
	int Send(vector<EccPoint>& points);


	/*
	*	@brief 接收对端发送的数据
	*	@returns 一组EccPoint类型的数据
	*/
	bool Recv();


	/*
	*	@brief 检测是否正常连接
	*	@returns 1 if connected, 0 otherwise
	*/
	bool isConnected();

private:
	uint8_t* m_priKey;            //私钥
	vector<uint8_t*> m_pubKey_x;  //公钥横坐标x集合
	vector<uint8_t*> m_pubKey_y;  //公钥纵坐标y集合
	SOCKET mSocket;               //服务端下的socket变量
	sockaddr_in mAddr;            //服务端的socket地址 
	sockaddr_in clientsAddr;       //客户端的socket地址 
	vector<SOCKET> clientsSocket;  //已连接的客户端的socket变量(用于后续的对点发送)
};

#endif