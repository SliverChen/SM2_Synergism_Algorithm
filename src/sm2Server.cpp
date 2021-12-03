#include"sm2Server.h"

SM2Server::SM2Server(int port)
{
	//初始化wsa环境
	WORD sockVersion = MAKEWORD(2, 2);
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		MES_ERROR("cannot start wsa,please check socket version\n");
		WSACleanup();
		exit(-1);
	}

	//初始化socket变量
	if ((mSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		MES_ERROR("cannot create the socket, please check your settings\n");
		exit(-1);
	}


	//初始化sockaddr变量
	mAddr.sin_family = AF_INET;
	mAddr.sin_addr.s_addr = INADDR_ANY;
	mAddr.sin_port = htons(port);


	//为socket变量和socketaddr变量进行绑定的操作
	if (bind(mSocket, (SOCKADDR*)&mAddr, sizeof(mAddr)) == SOCKET_ERROR)
	{
		MES_ERROR("can not bind the socket and sockAddr,please check the settings\n");
		exit(-1);
	}

	//开辟内存存储私钥
	m_priKey = new uint8_t[NUM_ECC_DIGITS];
}


//有待修改
SM2Server::~SM2Server()
{
	//释放socket变量
	if(mSocket != INVALID_SOCKET)
		closesocket(mSocket);

	//释放WSA环境
	WSACleanup();

	//释放私钥和公钥内容
	FREEARRAY(m_priKey);
	m_pubKey_x.clear();
	m_pubKey_y.clear();
}


void SM2Server::create_private_key()
{
	//1、生成私钥字符串(64位字符串)
	uint8_t* priKey_Str = nullptr;
	makeRandom(priKey_Str);

	//2、将字符串转换为uint8_t[NUM_ECC_DIGITS]的形式
	tohex(priKey_Str, m_priKey, NUM_ECC_DIGITS);
}


EccPoint SM2Server::getPublicKey(int index)
{
	EccPoint point;
	vli_set(m_pubKey_x[index], &point.x);
	vli_set(m_pubKey_y[index], &point.y);
	return point;
}


void SM2Server::listenClient()
{
	MES_INFO("waiting for the connecting..\n");

	//第二个参数设置的是待处理连接请求的最大长度
	if (listen(mSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		MES_ERROR("unexpected error in function 'listen'\n");
		exit(-1);
	}

	int clientAddrLen = sizeof(sockaddr_in);

	SOCKET client;
	socketaddr_in clientAddr;
	if ((client = accept(mSocket, (SOCKADDR*)&clientAddr, &clientAddrLen)) == SOCKET_ERROR)
	{
		MES_ERROR("unexpected error in function 'accept'\n");
		exit(-1);
	}

	//inet_ntoa: 将ip地址转换为十进制的形式
	MES_INFO("successfully connecting with %s \n", inet_ntoa(clientAddr.sin_addr));
}

int SM2Server::disconnect()
{
	if (mSocket != INVALID_SOCKET)
	{
		closesocket(mSocket);
	}

	return 1;
}

int SM2Server::Send(veector<EccPoint>& points)
{
	/*
	*  这里不需要对数据添加数据标识
	*  因为客户端是主动发送的一方，本身清楚数据在哪个步骤被使用
	*  但是这里的发送需要指明客户端的socket变量
	*/

	MES_INFO("sending data to the client..\n");

	//1、数据处理
	int size = points->size();

	/* 传输数据的格式： 点数量 + 点数据 */
	string buffer = to_string(size);

	string point_str;
	for (auto point : points)
	{
		//采用32个两位的16进制作为点数据的传输格式
		tostr(point.x, point_str, NUM_ECC_DIGITS);
		buffer.append(point_str);

		tostr(point.y, point_str, NUM_ECC_DIGITS);
		buffer.append(point_str);
	}

#ifdef __SM2_DEBUG__
	MES_INFO("the sending data is: %s\n",buffer);
#endif //__SM2_DEBUG__

	//2、数据传输
	const char* mess = buffer.c_str();

	/* 这里需要指明发送的客户端socket对象 */
	int ret = send(clientsSocket[0], mess, strlen(mess), 0);
	if (ret == SOCKET_ERROR || ret == 0)
	{
		if (mSocket == INVALID_SOCKET)
		{
			MES_ERROR("the server socket is invalid\n");
		}
		MES_ERROR("can not send the message, please check the sockAddr.\n");
		return 0;
	}

	MES_INFO("successfully sending data to client.\n");

	//3、释放内存
	delete mess;

	return 1;
}

bool SM2Server::Recv()
{
	//1、接收数据
	char data[65535];
	int ret;
	while ((ret = recv(mSocket, data, 65535, 0)) <= 0 && errno == EINTR)
	{
		Sleep(1);
	}

	//1.1 利用接收函数检测连接有效性
	if (ret <= 0 && errno != EINTR)
	{
		MES_ERROR("the connection has closed, shut down the calculating\n");
		return 0;
	}

	data[ret] = '\0';  //如果成功接收,则recv()返回的是数据的长度
	MES_INFO("receiving the data from client, transforming data..\n");

	//2、数据处理(从char[65535]中提取数据标识,数据长度,数据本身，并将数据转换为EccPoint类型)
	//数据的结构: 首部(标识+长度)+数据
	
	//2.1 提取数据的首部信息(数据的标识和点的数量)
	int singal = atoi(data[0]);
	int length = atoi(data[1]);

	//2.2 提取点
	vector<EccPoint> points;
	EccPoint point;

	char* tempData = new char[NUM_ECC_DIGITS * 2];
	uint8_t* data_convrt = new uint8_t[NUM_ECC_DIGITS];
	for (int i = 0; i < length; ++i)
	{
		memcpy(tempData, &data[i * NUM_ECC_DIGITS * 4 + 2], NUM_ECC_DIGITS * 2);

#ifdef __SM2_DEBUG__
		MES_INFO("the No.%d receiving data1: %s\n",i+1,tempData);
#endif //__SM2_DEBUG__

		data_convrt = reinterpret_cast<uint8_t*>(tempData);
		tohex(data_convrt, &point.x, NUM_ECC_DIGITS);
	
		memcpy(tempData, &data[i * NUM_ECC_DIGITS * 4 + 2 + NUM_ECC_DIGITS * 2], NUM_ECC_DIGITS * 2);

#ifdef __SM2_DEBUG__
		MES_INFO("the No.%d receiving data2: %s\n",i+1,tempData);
#endif //__SM2_DEBUG__

		data_convrt = reinterpret_cast<uint8_t*>(tempData);
		tohex(data_convrt, &point.y, NUM_ECC_DIGITS);
	
		points.push_back(point);
	}

	MES_INFO("successfully transforming data\n");

	//3、根据标识调用特定的数据计算函数
	bool flag = false;
	switch (signal) {
	case PUBLICKEY_P1:
		flag = CalData_createPubKey(points);
		break;

	case DECRYPT_Q1:
		flag = CalData_decrypt(points);
		break;

	case SIGN_P1:
		flag = CalData_sign(points);
		break;

	default:
		MES_ERROR("can not analysis the singal, which is %d\n",signal);
		break;
	};

	return flag;
}

bool SM2Server::CalData_createPubKey(vector<EccPoint>& points)
{

	/*
		这里需要注意一个问题
		当服务端计算好公钥时，如何将公钥对外公开？
		方案一：我们在通用类下创建一个公钥的静态成员
		当我们修改这个静态成员时，它的所有派生类下的公钥都将被同步修改
		这个方案不太适用
		原因：服务端与客户端是在不同程序下运行，静态成员无法跨越程序

		方案二：在计算好之后将结果也发送给客户端
		这样会耗费一次发送接收的时间(目前没有想到更好的办法)
	*/


	//1、接收d1G
	
	//2、计算d1d2G
	EccPoint d1d2G;
	EccPoint_mult(&d1d2G,&points[0],m_priKey,NULL);

	//3、计算P = d1d2G - G
	

}


bool SM2Server::CalData_sign(vector<EccPoint>& points)
{

}

bool SM2Server::CalData_decrypt(vector<EccPoint>& points)
{

}

