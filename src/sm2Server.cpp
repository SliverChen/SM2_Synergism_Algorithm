#include"sm2Server.h"

SM2Server::SM2Server()
{
	//初始化wsa环境
	WORD sockVersion = MAKEWORD(2, 2);
	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		MES_ERROR << "cannot start wsa,please check socket version\n";
		WSACleanup();
		exit(-1);
	}

	//初始化socket变量
	if ((mSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	{
		MES_ERROR << "cannot create the socket, please check your settings\n";
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

}

int SM2Server::disconnect()
{

}

int SM2Server::Send(veector<EccPoint>& points)
{

}

vector<EccPoint> Recv()
{

}

bool SM2Server::CalData_createPubKey(EccPoint& point)
{

}


bool SM2Server::CalData_sign()
{

}

bool SM2Server::CalData_decrypt()
{

}

