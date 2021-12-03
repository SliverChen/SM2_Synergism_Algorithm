#include"./src/sm2.h"

int main()
{
	if (EccPoint_is_on_curve(curve_G))
	{
		MES_INFO("the G is on the curve\n");
	}
	else
	{
		MES_ERROR("the G is not on the curve\n");
	}
	return 0;
}