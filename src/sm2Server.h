#ifndef HEADER_SM2SERVER_H
#define HEADER_SM2SERVER_H

#pragma once

#include"sock_param.h"

/*
*	@brief SM2�������
*	���ڱ�ʾSM2�µķ����
*/
class SM2Server : public SM2Socket
{
public:
	/*
	*	@brief ��ʼ��socket������socket����
	*/
	SM2Server();

	/*
	* �ͷ��ڴ棬�������
	*/
	~SM2Server();

	/*
	*	@brief ����˽Կ
	*/
	void create_private_key();

	/*
	*	@brief ��ȡ�����ɵĹ�Կ
	*	@returns EccPoint��ʽ�Ĺ�Կ
	*/
	EccPoint getPublicKey(int index);


	void listenClient();

private:
	/*
	*	@brief Эͬ����ǩ��(Э����)
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_sign();

	/*
	*	@brief �����Эͬ�������(Э����)
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_decrypt();

	/*
	*	@brief Эͬ���㹫Կ
	*	@param point �ͻ��˼�����м�ֵ
	*	@returns 1 if success, 0 otherwise
	*/
	bool CalData_createPubKey(EccPoint& point);


	/*
	*	@brief �Ͽ���ͻ��˵�����
	*	@returns 1 if success, 0 otherwise
	*/
	int disconnect();

	/*
	*	@brief �������ݵ��Զ�
	*	@param points: ��Ҫ���͵��ɶ��EccPoint���ݹ��ɵ�����
	*	@returns 1 if success, 0 otherwise
	*/
	int Send(vector<EccPoint>& points);


	/*
	*	@brief ���նԶ˷��͵�����
	*	@returns ��һ������EccPoint���ݹ��ɵ�����
	*/
	vector<EccPoint> Recv();


	/*
	*	@brief �ж��Ƿ�����
	*	@returns 1 if connected, 0 otherwise
	*/
	bool isConnected();

private:
	uint8_t* m_priKey;            //˽Կ
	vector<uint8_t*> m_pubKey_x;  //���пͻ��˹�Կ����Բ�����µ�x
	vector<uint8_t*> m_pubKey_y;  //���пͻ��˹�Կ����Բ�����µ�y
	SOCKET mSocket;               //�����socket����
	sockaddr mAddr;               //����˵ĵ�ַ��Ϣ 
	vector<SOCKET> clientSocket;  //�ͻ��˵�socket������
};

/*
* ���䣺�о�ʹ��vector����ͻ��˵�socket�͹�Կ�������ô���
* ����һ�£�����Ⱥ��������ͻ�������Эͬ���㣬�м�һ����Ϊ����ܿ���ǰ����������̣������б������
* �����ʱ�е��ĸ��ͻ�������Эͬ���㣬���Ǽ�¼��ǰ��������Щ�����ǿյ�
* ����ϵͳ�޷������жϵڶ���λ���ǿյģ�ֱ�Ӳ��뵽����
* ���һֱ���������Ĳ������������Ĺ�ģ�᲻�ϱ��������һЩû�б�Ҫ���ڴ�
*/