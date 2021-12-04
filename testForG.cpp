// #include"./src/sm2.h"

// int main()
// {
// 	uint8_t* randStr = (uint8_t*)"FFFFFF27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21";
// 	uint8_t* randStr2 = (uint8_t*)"B32C633B87A7C254775569158FB18557148A88CF60855F4064115471CEC0EF8B";
// 	uint8_t* p_random = new uint8_t[NUM_ECC_DIGITS];
// 	uint8_t tmp = 0x00;

// 	tohex(randStr2, p_random, NUM_ECC_DIGITS);

// 	/*for (int i = 0; i < NUM_ECC_DIGITS / 2; ++i)
// 	{
// 		tmp = p_random[i];
// 		p_random[i] = p_random[NUM_ECC_DIGITS - i - 1];
// 		p_random[NUM_ECC_DIGITS - i - 1] = tmp;
// 	}*/

// 	for (int i = 0; i < NUM_ECC_DIGITS; ++i)
// 	{
// 		printf("%02X", p_random[i]);
// 	}
// 	printf("\n");

// 	EccPoint C1;
// 	EccPoint_mult(&C1,&curve_G,p_random,NULL);

// 	//ţ��
// 	if (EccPoint_is_on_curve(C1))
// 	{
// 		printf("C1 is on the curve\n");
// 	}
// 	else
// 	{
// 		printf("C1 is not on the curve\n");
// 	}
// 	return 0;
// }