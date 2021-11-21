#ifndef HEADER_SM2SERVER_H
#define HEADER_SM2SERVER_H

#pragma once

#include"sock_param.h"

/*
*	@brief SM2服务端类
*	用于表示SM2下的服务端
*/
class SM2Server : public SM2Socket
{
public:
	/*
	*	@brief 初始化socket环境和socket变量
	*/
	SM2Server();

	/*
	* 释放内存，清除环境
	*/
	~SM2Server();

	/*
	*	@brief 生成私钥
	*/
	void create_private_key();

	/*
	*	@brief 获取已生成的公钥
	*	@returns EccPoint形式的公钥
	*/
	EccPoint getPublicKey(int index);


	void listenClient();

private:
	/*
	*	@brief 协同计算签名(协助方)
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_sign();

	/*
	*	@brief 服务端协同计算解密(协助方)
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_decrypt();

	/*
	*	@brief 协同计算公钥
	*	@param point 客户端计算的中间值
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_createPubKey(EccPoint& point);


	/*
	*	@brief 断开与客户端的连接
	*	@returns 1 if success, 0 otherwise
	*/
	int disconnect();

	/*
	*	@brief 发送数据到对端
	*	@param points: 将要发送的由多个EccPoint数据构成的数组
	*	@returns 1 if success, 0 otherwise
	*/
	int Send(vector<EccPoint>& points);


	/*
	*	@brief 接收对端发送的数据
	*	@returns 由一个或多个EccPoint数据构成的数组
	*/
	vector<EccPoint> Recv();


	/*
	*	@brief 判断是否连接
	*	@returns 1 if connected, 0 otherwise
	*/
	bool isConnected();

private:
	uint8_t* m_priKey;            //私钥
	vector<uint8_t*> m_pubKey_x;  //所有客户端公钥在椭圆曲线下的x
	vector<uint8_t*> m_pubKey_y;  //所有客户端公钥在椭圆曲线下的y
	SOCKET mSocket;               //服务端socket变量
	sockaddr mAddr;               //服务端的地址信息 
	vector<SOCKET> clientSocket;  //客户端的socket变量池
};

/*
* 补充：感觉使用vector管理客户端的socket和公钥后续不好处理
* 假设一下，如果先后有三个客户端申请协同计算，中间一个因为网络很快提前结束计算过程，并从列表中清除
* 如果此时有第四个客户端申请协同计算，除非记录当前数组有哪些索引是空的
* 否则系统无法自行判断第二个位置是空的，直接插入到后面
* 如果一直保持这样的操作，这个数组的规模会不断变大，消耗了一些没有必要的内存
*/