/*
     I can't get the idea of the paper clearly, so I write another possible way to get the chaotic 
	 sequence. Even the chaotic sequence may be different from the sequence gotten from the other
	 way. The different sequences DO NOT influence the CPA attack, anyway, LOL.
*/
//#define CIPHERTONG
#ifdef CIPHERTONG
#include <asf.h>
#include<stdio.h>
#include<stdint.h>
#include "cubic8.h"
#include"cipherTong.h"

uint8_t ROUND = 12;
#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//创建触发引脚
uint8_t roundKey1[12], roundKey2[12];//用来存储轮密钥

void encTxj(uint8_t* plaintext, uint8_t* ciphertext)
{
	uint8_t intermediateL[2], intermediateR[2];//加密过程中，中间值的左16bit和右16bit
	uint8_t ATT1, C1, C2, C3, C5, C6, C7, C8; uint16_t C4;//加密过程中的中间变量
	intermediateL[0] = plaintext[0]; intermediateL[1] = plaintext[1];
	intermediateR[0] = plaintext[2]; intermediateR[1] = plaintext[3];
	roundKeyGen(roundKey1,roundKey2);//Round key generation
	
	ioport_set_pin_high(TRIGGER);//set the PA0 to high to target the ADC
	nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();//nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();nop();//25nops i.e.100 clks
	
	for (uint8_t i = 0; i < ROUND; i++)//12 rounds of encryption
	{
		C7 = intermediateR[0]; C8 = intermediateR[1];
		C1 = intermediateR[0] ^ roundKey1[i];
		C2 = cubic8[(uint8_t)(intermediateR[1] + C1)]^roundKey2[i];
		
		ATT1= cubic8[C1];
		
		C3 = ATT1 + C2;
		C4 = (((uint16_t)C3) << 8) ^ (uint16_t)C2;
		C4 = pBox(C4);

		C5 = intermediateL[0] ^ (uint8_t)(C4 >> 8);
		C6 = intermediateL[1] ^ (uint8_t)(C4 & 0x00ff);

		if (i<ROUND - 1)
		{
			intermediateL[0] = C7; intermediateL[1] = C8;
			intermediateR[0] = C5; intermediateR[1] = C6;
		}
		else//最后一轮不进行左右对调
		{
			intermediateL[0] = C5; intermediateL[1] = C6;
			intermediateR[0] = C7; intermediateR[1] = C8;
		}
	}
	ioport_set_pin_low(TRIGGER);
	
	ciphertext[0] = intermediateL[0]; ciphertext[1] = intermediateL[1];
	ciphertext[2] = intermediateR[0]; ciphertext[3] = intermediateR[1];
}

//************************** Master and Round Key Generation ********************************//
void roundKeyGen(uint8_t *roundKey1, uint8_t *roundKey2)//
{
	//Master key generation
	uint8_t k[16];//Master key
	uint32_t s[4];//chaotic sequence( four 32-bit values )
	seqGen(1299, s);//chaotic sequence generation

	for (uint8_t i = 0; i < 16; i++)//将4个32bit长的序列分为16个8bit作为主密钥
	{
		switch (i % 4)
		{
		case 0:
			k[i] = (s[i / 4] & 0xff000000) >> 24; break;
		case 1:
			k[i] = (s[i / 4] & 0x00ff0000) >> 16; break;
		case 2:
			k[i] = (s[i / 4] & 0x0000ff00) >> 8; break;
		case 3:
			k[i] = (s[i / 4] & 0x000000ff); break;
		default:
			break;
		}
	}
	//Round key generation. This algorithm contains 12 rounds of encryption process, and each round uses two 8-bits round keys.
	for (size_t j = 0; j < 12; j++)
	{
		//生成轮密钥部分，偶数项通过立方映射
		for (uint8_t i = 1; i < 16; i = i + 2)
			k[i] = cubic8[k[i]];

		for (uint8_t i = 0; i < 16; i = i + 2)//奇数项和后一个偶数项相异或，异或结果通过立方映射
		{
			k[i] = k[i] ^ k[i + 1];
			k[i] = cubic8[k[i]];
			uint16_t kn;//将前后两个字节组合起来，将16位结果通过p盒置换，形如x2x1
			kn = (((uint16_t)k[i + 1]) << 8) ^ ((uint16_t)k[i]);
			kn = pBox(kn);
			k[i + 1] = (uint8_t)((kn & 0xff00) >> 8);//将16bit的值分为两个8bit值
			k[i] = (uint8_t)(kn & 0x00ff);
		}
		//将全部128bit值左移5位
		uint8_t shiftTemp = 0;
		shiftTemp = k[0] >> 3;//左移5位移出去的数字和右移3位剩下的数字是一样的
		k[0] <<= 5;
		for (uint8_t i = 1; i < 16; i++)//将15个字节的主密钥依次向左移5bit
		{
			k[i - 1] = k[i - 1] | (k[i] >> 3);
			k[i] = k[i] << 5;
		}
		k[15] |= shiftTemp;
		roundKey1[j] = k[0] ^ k[8];
		roundKey2[j] = k[4] ^ k[12];
	}
}

uint16_t pBox(uint16_t x)//bitwise permutation
{
	uint8_t pTable[16] = { 9,6,11,8,15,12,2,13,10,4,0,14,3,5,7,1 };
	uint16_t temp = 0, mask = 1;
	for (uint8_t i = 0; i < 16; i++)
	{
		if (x&((uint16_t)(mask << i)))
		{
			temp = temp | (uint16_t)(mask << pTable[i]);
		}
		else
		{
			temp = temp & (uint16_t)(~(uint16_t)(mask << pTable[i]));
		}
	}
	return temp;
	//printf("%u",temp);
}

//************************** Chaotic Sequence Generation ********************************//
void seqGen(uint32_t x, uint32_t* outArr)//sequence generation
{
	uint32_t xx = x, yy = x, zz = x, M = 10;
	uint32_t xArr[4], yArr[4], zArr[4];
	
	for (uint8_t i = 0; i < M; i++)
	{
		xx = cubic32(linearCongruence(xx));
		if (i>=(M-4))
		{
			xArr[i - (M - 4)] = xx;
		}
	}
	for (uint8_t i = 0; i < M; i++)
	{
		yy = logistic(yy);
		if (i>=(M-4))
		{
			yArr[i - (M - 4)] = yy;
		}
	}
	for (uint8_t i = 0; i < M; i++)
	{
		zz = linearCongruence(zz);
		if (i>=(M-4))
		{
			zArr[i - (M - 4)] = zz;
		}
	}
	for (int i = 0; i < 4; i++)
	{
		outArr[i] = xArr[i] ^ yArr[i] ^ zArr[i];
	}
}
//**************************整数化Logistic映射********************************//
uint32_t logistic(uint32_t x)
{
	uint64_t xn = x;
	return ((uint32_t)((xn << 2) - ((xn*xn) >> 30)));
}
//************************** Integer Cubic map ********************************//
//uint8_t cubic8(uint8_t x)
//{
	//uint32_t xn = x;
	//uint8_t tem = (uint8_t)(((xn*xn*xn) >> 12) + (9 * xn) - ((3 * xn*xn) >> 5));
	//if (xn == 0 || xn == 192)
	//{
		//return tem + 1;
	//}
	//if (tem == 0)
	//{
		//return (2 * x);
	//}
	//if (xn == 128)
	//{
		//return tem - 1;
	//}
	//else
	//{
		//return tem;
	//}
//
//}
uint32_t cubic32(uint32_t x)//32bit Cubic map
{
	uint64_t tem=0; uint64_t xn = x;
	if (xn <= 2097152)//xn<=2^21
	{
		tem = (uint64_t)(((xn*xn*xn) >> 60) + (9 * xn) - ((3 * xn*xn) >> 29));
	}
	if ((2097152<xn) && (xn <= 1073741824))//2^21<xn<=2^30
	{
		tem = (uint64_t)(((((xn*xn) >> 30)*xn) >> 30) + (9 * xn) - ((3 * xn*xn) >> 29));
	}
	if (1073741824<xn)//2^30<xn
	{
		tem = (uint64_t)(((((xn*xn) >> 32)*xn) >> 28) + (9 * xn) - (3 * ((xn *xn) >> 29)));
	}

	if (xn == 0 || xn == 3221225472)//x==0 or 1.5C
	{
		return(tem + 1);
	}

	if (xn == 2147483648)//x==C
	{
		return(tem - 1);
	}
	else {
		return(tem);
	}
}
//**************************线性同余映射********************************//
uint32_t linearCongruence(uint32_t x)
{
	uint64_t xn = x;
	//return((uint32_t)((214013 * xn + 2531011) % 4294967295));
	return((uint32_t)((16807 * xn) % 2147483647));
}
#endif