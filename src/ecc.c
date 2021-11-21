#include"ecc.h"

#ifdef __cplusplus
extern "C"{
#endif //__cplusplus

	void makeRandom(uint8_t*& randStr)
	{
		/* 1、将基点的阶curve_n转换为hex的字符串 */
		string curveN_str;
		tostr(curve_n, curveN_str, NUM_ECC_DIGITS);
		char* curveN = const_cast<char*>(curveN_str.c_str());

		/* 2、将转换后的hex字符串转换为BIGNUM类型(用于后续限定随机数生成的范围) */
		BIGNUM* cn = BN_hex2bn(curveN);

		/* 3、生成随机数 */
		BIGNUM* bn = BN_new(); //需要先申请空间，不然会出错

		//比特长度
		int bits = 8 * NUM_ECC_DIGITS;

		//BN_rand_range: 生成[0,range)的随机数
		//参考: https://www.openssl.org/docs/man3.0/man3/BN_rand_range.html

		//随机数需要的区间为[1,n-1],由于该函数会生成0
		//因此需要检验生成数是否为0，如果是则需要重新生成
		do
		{
			BN_rand_range(bn, cn);
		} while (BN_is_zero(bn));

		//将BIGNUM转换为16进制的char*字符串
		char* str = BN_bn2hex(bn);

		//将char* 转换为unsigned char*
		//(只能使用强制类型转换,无法使用static_cast，因为这两个是不同的类型)
		//只有char 和 unsigned char能进行static_cast的转换
		randStr = reinterpret_cast<unsigned char*>(str);

#ifdef __SM2_DEBUG__
		MES_INFO << " the random is defined as: " << randStr << endl;
#endif //__SM2_DEBUG__

		/* 4、释放BIGNUM内存 */
		BN_free(bn);
		BN_free(cn);
	}

	void ecc_bytes2native(uint8_t p_bytes[NUM_ECC_DIGITS * 4], uint8_t P_native[NUM_ECC_DIGITS])
	{
		unsigned int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i)
		{
			p_bytes[NUM_ECC_DIGITS - i - 1] = p_native[i];
		}
	}

	void ecc_native2bytes(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS * 4])
	{
		unsigned int i;
		for (i = 0; i < NUM_ECC_DIGITS; ++i)
		{
			p_native[i] = p_bytes[NUM_ECC_DIGITS - i - 1];
		}
	}

	static int EccPoint_isZero(EccPoint* p_point)
	{
		return (vli_isZero(p_point->x) && vli_isZero(p_point->y));
	}

	static int EccPoint_is_on_curve(const EccPoint& p_point)
	{

	}

	static void EccPoint_double_jacobian(uint8_t* X1, uint8_t* Y1, uint8_t* Z1)
	{
		/* t1 = X, t2 = Y, t3 = Z */
		uint8_t t4[NUM_ECC_DIGITS];
		uint8_t t5[NUM_ECC_DIGITS];

		if (vli_isZero(Z1))
		{
			return;
		}

		vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
		vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
		vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
		vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
		vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

		vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
		vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
		vli_modSub(Z1, X1, Z1, curve_p); /* t3 = x1 - z1^2 */
		vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

		vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
		vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
		if (vli_testBit(X1, 0))
		{
			uint8_t l_carry = vli_add(X1, X1, curve_p);
			vli_rshift1(X1);
			X1[NUM_ECC_DIGITS - 1] |= l_carry << 7;
		}
		else
		{
			vli_rshift1(X1);
		}
		/* t1 = 3/2*(x1^2 - z1^4) = B */

		vli_modSquare_fast(Z1, X1);      /* t3 = B^2 */
		vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - A */
		vli_modSub(Z1, Z1, t5, curve_p); /* t3 = B^2 - 2A = x3 */
		vli_modSub(t5, t5, Z1, curve_p); /* t5 = A - x3 */
		vli_modMult_fast(X1, X1, t5);    /* t1 = B * (A - x3) */
		vli_modSub(t4, X1, t4, curve_p); /* t4 = B * (A - x3) - y1^4 = y3 */

		vli_set(X1, Z1);
		vli_set(Z1, Y1);
		vli_set(Y1, t4);
	}

	static void apply_z(uint8_t* X1, uint8_t* Y1, uint8_t* Z1)
	{
		uint8_t t1[NUM_ECC_DIGITS];

		vli_modSquare_fast(t1, Z);    /* z^2 */
		vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
		vli_modMult_fast(t1, t1, Z);  /* z^3 */
		vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
	}

	static void XYcZ_initial_double(uint8_t* X1, uint8_t* Y1, uint8_t* X2, uint8_t* Y2)
	{
		uint8_t z[NUM_ECC_DIGITS];

		vli_set(X2, X1);
		vli_set(Y2, Y1);

		vli_clear(z);
		z[0] = 1;
		if (p_initialZ)
		{
			vli_set(z, p_initialZ);
		}
		apply_z(X1, Y1, z);

		EccPoint_double_jacobian(X1, Y1, z);

		apply_z(X2, Y2, z);
	}

	static void XYcZ_add(uint8_t* X1, uint8_t* Y1, uint8_t* X2, uint8_t* Y2)
	{
		/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
		uint8_t t5[NUM_ECC_DIGITS];

		//X3 = D ? (B + C) ; Y3 = (Y2 ? Y1)(B ? X3) ? E and Z3 = Z(X2 ? X1) 
		//A = (X2 ? X1)2, B = X1A, C = X2A, D = (Y2 ? Y1)2 and E = Y1(C ? B)

		vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
		vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
		vli_modMult_fast(X1, X1, t5);    /* X1 = t1 = x1*A = B */
		vli_modMult_fast(X2, X2, t5);    /* X2 = t3 = x2*A = C */
		vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y2 - y1 */
		vli_modSquare_fast(t5, Y2);      /* t5 = (y2 - y1)^2 = D */

	//X3 = D ? (B + C)
		vli_modSub(t5, t5, X1, curve_p); /* t5 = D - B */
		vli_modSub(t5, t5, X2, curve_p); /* t5 = D - B - C = x3 */

		vli_modSub(X2, X2, X1, curve_p); /* X2 = t3 = C - B */
		vli_modMult_fast(Y1, Y1, X2);    /* Y1 = t2 = y1*(C - B) = E*/
		vli_modSub(X2, X1, t5, curve_p); /* X2 = t3 = B - x3 */
		vli_modMult_fast(Y2, Y2, X2);    /* Y2 = t4 = (y2 - y1)*(B - x3) */
	//y2=y3
		vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y3 */

	//x2=t5=x3
		vli_set(X2, t5);
	}

	static void XYcZ_addC(uint8_t* X1, uint8_t* Y1, uint8_t* X2, uint8_t* Y2)
	{
		/* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
		uint8_t t5[NUM_ECC_DIGITS];
		uint8_t t6[NUM_ECC_DIGITS];
		uint8_t t7[NUM_ECC_DIGITS];

	//s1
		vli_modSub(t5, X2, X1, curve_p); /* t5 = x2 - x1 */
		vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
	//s2
		vli_modMult_fast(X1, X1, t5);    /* X1 = t1 = x1*A = B */
	//s3
		vli_modMult_fast(X2, X2, t5);    /* X2 = t3 = x2*A = C */

	//s4
		vli_modAdd(t5, Y2, Y1, curve_p); /* t5 = t4 = y2 + y1 */
		vli_modSub(Y2, Y2, Y1, curve_p); /* Y2 = t4 = y2 - y1 */

	//s5 :E = Y1(C ? B)
		vli_modSub(t6, X2, X1, curve_p); /* t6 = C - B */
		vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) */
	//s6 :B + C
		vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
	//s4:D=(Y2 ? Y1)^2
		vli_modSquare_fast(X2, Y2);      /* X2 = t3 = (y2 - y1)^2 */
	//s6:X3=D ? (B + C)
		vli_modSub(X2, X2, t6, curve_p); /* X2 = t3 = x3 */

	//s7:Y3 = (Y2 ? Y1)(B ? X3) ? E
		vli_modSub(t7, X1, X2, curve_p); /* t7 = B - x3 */
		vli_modMult_fast(Y2, Y2, t7);    /* t4 = (y2 - y1)*(B - x3) */
		vli_modSub(Y2, Y2, Y1, curve_p); /* t4 = y3 */

	//s4
		vli_modSquare_fast(t7, t5);      /* t7 = (y2 + y1)^2 = F */

	//s8:F-(B+C)
		vli_modSub(t7, t7, t6, curve_p); /* t7 = x3' */

	//s9
		vli_modSub(t6, t7, X1, curve_p); /* t6 = x3' - B */
		vli_modMult_fast(t6, t6, t5);    /* t6 = (y2 + y1)*(x3' - B) */
		vli_modSub(Y1, t6, Y1, curve_p); /* t2 = y3' */

		vli_set(X1, t7);
	}

	static void EccPoint_mult(EccPoint* p_result, EccPoint* p_point,
		uint8_t* p_scalar, uint8_t* p_initialZ)
	{
		/* R0 and R1 */
		uint8_t Rx[2][NUM_ECC_DIGITS];
		uint8_t Ry[2][NUM_ECC_DIGITS];
		uint8_t z[NUM_ECC_DIGITS];

		unsigned int i, nb;

		vli_set(Rx[1], p_point->x);
		vli_set(Ry[1], p_point->y);

		XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], p_initialZ);

		for (i = vli_numBits(p_scalar) - 2; i > 0; --i)
		{
			nb = !vli_testBit(p_scalar, i);
			XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
			XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
		}

		nb = !vli_testBit(p_scalar, 0);
		XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

		/* Find final 1/Z value. */
		vli_modSub(z, Rx[1], Rx[0], curve_p); /* X1 - X0 */
		vli_modMult_fast(z, z, Ry[1 - nb]);     /* Yb * (X1 - X0) */
		vli_modMult_fast(z, z, p_point->x);   /* xP * Yb * (X1 - X0) */
		vli_modInv(z, z, curve_p);            /* 1 / (xP * Yb * (X1 - X0)) */
		vli_modMult_fast(z, z, p_point->y);   /* yP / (xP * Yb * (X1 - X0)) */
		vli_modMult_fast(z, z, Rx[1 - nb]);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
		/* End 1/Z calculation */

		XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);

		apply_z(Rx[0], Ry[0], z);

		vli_set(p_result->x, Rx[0]);
		vli_set(p_result->y, Ry[0]);
	}

	int ecc_make_key(EccPoint* p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS],
		uint8_t p_random[NUM_ECC_DIGITS])
	{
		/* Make sure the private key is in the range [1, n-1].
	   For the supported curves, n is always large enough that we only need to subtract once at most. */
		vli_set(p_privateKey, p_random);
		if (vli_cmp(curve_n, p_privateKey) != 1)
		{
			vli_sub(p_privateKey, p_privateKey, curve_n);
		}

		if (vli_isZero(p_privateKey))
		{
			return 0; /* The private key cannot be 0 (mod p). */
		}

		EccPoint_mult(p_publicKey, &curve_G, p_privateKey, NULL);
		return 1;
	}

	int ecc_valid_public_key(EccPoint* p_publicKey)
	{
		uint8_t na[NUM_ECC_DIGITS] = { 3 }; /* a mod p = (-3) mod p */

		uint8_t l_tmp1[NUM_ECC_DIGITS];
		uint8_t l_tmp2[NUM_ECC_DIGITS];

		if (EccPoint_isZero(p_publicKey))
		{
			return 0;
		}

		if (vli_cmp(curve_p, p_publicKey->x) != 1 || vli_cmp(curve_p, p_publicKey->y) != 1)
		{
			return 0;
		}

		vli_modSquare_fast(l_tmp1, p_publicKey->y); /* tmp1 = y^2 */
		vli_modSquare_fast(l_tmp2, p_publicKey->x); /* tmp2 = x^2 */
		vli_modSub(l_tmp2, l_tmp2, na, curve_p);  /* tmp2 = x^2 + a = x^2 - 3 */
		vli_modMult_fast(l_tmp2, l_tmp2, p_publicKey->x); /* tmp2 = x^3 + ax */
		vli_modAdd(l_tmp2, l_tmp2, curve_b, curve_p); /* tmp2 = x^3 + ax + b */

		/* Make sure that y^2 == x^3 + ax + b */
		if (vli_cmp(l_tmp1, l_tmp2) != 0)
		{
			return 0;
		}

		return 1;
	}

	int ecdh_shared_secret(uint8_t p_seret[NUM_ECC_DIGITS], EccPoint* p_publicKey,
		uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS])
	{
		EccPoint l_product;

		EccPoint_mult(&l_product, p_publicKey, p_privateKey, p_random);
		if (EccPoint_isZero(&l_product))
		{
			return 0;
		}

		vli_set(p_secret, l_product.x);

		return 1;
	}