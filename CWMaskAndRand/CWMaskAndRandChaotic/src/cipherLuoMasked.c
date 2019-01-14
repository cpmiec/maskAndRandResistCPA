/*
 * maskedChaoticEnc.c
 * 加入随机掩码和随机化操作防止旁路攻击
 * Created: 2018/3/26 20:58:51
 *  Author: Dell
 */ 
#define CIPHERLUOMASKED
#ifdef CIPHERLUOMASKED
#include <asf.h>
#include <stdint.h>
#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//创建触发引脚

#define ROUND 3

extern uint8_t key[];//密钥
uint8_t RDKey[ROUND*16];//Round key

float seed = 0;//生成掩码所需种子
uint8_t s_mask_1, s_mask_2,add_mask[16],mul_mask_1,mul_mask_2;//所用掩码
uint8_t seqCtrl[16]={0};//randomize the sequence of the s-box and
uint8_t msbox[256];//掩码sbox
uint8_t sbox[256] = {//线性替换表
	//  0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F
uint8_t inv[256] ={//有限域乘法的逆
	//  0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7,//0
	0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2,//1
	0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,//2
	0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19,//3
	0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09,//4
	0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,//5
	0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b,//6
	0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82,//7
	0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,//8
	0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a,//9
	0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62,//A
	0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,//B
	0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6,//C
	0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b,//D
	0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,//E
0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c };//F

float tentn(float xn, float a);//帐篷映射
void roundKeyGen(float x0, uint8_t randnum[]);
void addroundkey(uint8_t	*interarray, uint8_t *roundkey);
void getboxvalue(uint8_t interarray[], uint8_t box[]);
uint8_t XTIME(unsigned char x);
uint8_t multiply(unsigned char a, unsigned char b);
void diffusionmodule(uint8_t interarray[]);
void indiffusionmodule(uint8_t interarray[]);
void catmap(uint8_t origin[], uint8_t count, uint8_t a, uint8_t b);//a,b:猫映射系

//掩码部分
void mask_gen(float x0);//生成掩码
void cons_sbox(uint8_t mask_before, uint8_t mask_after);//construct_sbox构造 S-box
void mask_all(uint8_t[], uint8_t mask);//对数组的全体使用mask进行掩码
void genDiffNum(float xn,float a,uint8_t valueRange, uint8_t randSeq[]);

void sendUint16(uint16_t value16);//通过串口返回一个uint16类型的数据

uint8_t intermediate[16];

void encInit( void )
{
	roundKeyGen((float)0.5987, RDKey);
}
void encLuoMasked(uint8_t ciphertext[], uint8_t plaintext[])
{
	for (uint8_t i = 0; i < 16; i++)
		intermediate[i] = plaintext[i];
	
	encInit();
	////////////////////////////////////////////////////////////////////////////////////
	mask_gen(seed);//掩码生成
	cons_sbox(s_mask_1, s_mask_2);//生成新sbox
	ioport_set_pin_high(TRIGGER);//置高 PA0，触发能耗统计
	mask_all(intermediate, s_mask_1);//
	
	for (uint8_t i = 0; i < ROUND; i++)
	{
		addroundkey(intermediate, RDKey + 16 * i);//i是指轮数，RDKey+16*i是指选择哪一轮轮密钥//
		getboxvalue(intermediate, msbox);//
		diffusionmodule(intermediate);
		catmap(intermediate, 1, 1, 1);
	}
	mask_all(intermediate,s_mask_1);

	ioport_set_pin_low(TRIGGER);//置零 PA0，触发能耗统计停止
	
	for (uint8_t i = 0; i < 16; i++)
		ciphertext[i] = RDKey[i];
}

//**************************Round Key Gen*****************************//
void roundKeyGen(float x0, uint8_t randnum[])//num指丢弃前多少个值
{
	float xn = x0; float a;
	for (uint8_t i = 0; i < 16; i++)
	{
		a = (float)0.51 + (float)key[i] / 1000;
		for (uint8_t j = 0; j < 20; j++)
		{
			xn = tentn(xn, a);
		}
	}
	
	for (uint8_t i = 0; i < 100; i++)
	{
		xn=tentn(xn,a);
	}
	
	for (uint8_t i = 0; i < 16 * ROUND; i++)
	{
		xn = tentn(xn, a);
		randnum[i] = (uint8_t)(xn * 256);
	}
	seed = tentn(xn, a);
}

//通过Hash函数生成掩码，x0为Hash函数的初始值，a为参数//
void mask_gen(float x0)//生成掩码
{
	float a;
	float xn = x0;
	for (uint8_t i = 0; i < 16; i++)
	{
		a = (float)0.51 + (float)0.001*intermediate[i];
		for (uint8_t j = 0; j < 10; j++)
		{
			xn = tentn(xn, a);
		}
	}
	xn = tentn(xn, a);
	s_mask_1 = (uint8_t)(255 * xn);
	xn = tentn(xn, a);
	s_mask_2 = (uint8_t)(255 * xn);

	for (uint8_t i = 0; i < 16; i++)
	{
		xn = tentn(xn, a);
		add_mask[i] = (uint8_t)(255*xn) ;
	}
	xn = tentn(xn, a);
	mul_mask_1 = (uint8_t)(255*xn);
	do //generate the non-zero value used for mul-mask
	{
		xn = tentn(xn, a);
	} while ((mul_mask_2 = (uint8_t)(255*xn))==0);
	genDiffNum(xn,a,16,seqCtrl);
}

void genDiffNum(float xn,float a,uint8_t valueRange, uint8_t randSeq[])//generate 16 different values between 0-valueRange-1
{
	
	uint8_t nonZeroCount=0, randIndex=0, randTem=0;
	uint8_t *randFlag;
	randFlag=(uint8_t*)malloc(sizeof(uint8_t)*valueRange);
	for (uint8_t i=0;i<16;i++)
	{
		randFlag[i]=0;
	}
	while(nonZeroCount<16)//generate 16 different values.
	{
		for (uint8_t i=0;i<2;i++)
		{
			xn = tentn(xn, a);
		}
			
		randTem=((uint8_t)(255*xn))%valueRange;
		if (randFlag[randTem]==0)
		{
			randSeq[randIndex]=randTem;
			randFlag[randTem]=1;
			randIndex++;
			}else{
			xn=(float)(0.9)*xn+0.05;
		}
		
		//check out whether all the values are generated.	
		nonZeroCount=0;
		for (uint8_t i = 0; i < valueRange ; i++)
		{
			nonZeroCount+=randFlag[i];
		}
	}
	free(randFlag);
	randFlag=NULL;
}

//**************************构建新的sbox**************************//
void cons_sbox(uint8_t mask_in, uint8_t mask_out)//construct_sbox构造 S-box
{
	for (int i = 0; i < 256; i++)
	msbox[i^mask_in] = sbox[i] ^ mask_out;
}
//*************************对数组的全体元素使用mask进行掩码*********//
void mask_all(uint8_t arr[], uint8_t mask)//对数组的全体使用mask进行掩码
{
	for (uint8_t i = 0; i < 16; i++)
	arr[i] ^= mask;
}

//**************************Add Round Key*****************************//
void addroundkey(uint8_t *interarray, uint8_t *roundkey)//
{
	for (uint8_t i = 0; i < 16; i++)
	{
		interarray[seqCtrl[i]]^=roundkey[seqCtrl[i]];
	}
}

//**************************S-box变换********************************//
void getboxvalue(uint8_t interarray[], uint8_t box[])//进行S-box正变换或者反变换
{
	for (uint8_t i = 0; i < 16; i++)
	{
		interarray[seqCtrl[i]] = box[interarray[seqCtrl[i]]];
	}
}
//*************************扩散环节**********************************//
unsigned char XTIME(unsigned char x)
{
	return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

unsigned char multiply(unsigned char a, unsigned char b)
{
	unsigned char temp[8] = { a };
	unsigned char tempmultiply = 0x00;
	for (int i = 1; i < 8; i++)
	{
		temp[i] = XTIME(temp[i - 1]);
	}
	tempmultiply = (b & 0x01)*a;
	for (int i = 1; i < 8; i++)
	{
		tempmultiply ^= (((b >> i) & 0x01)*temp[i]);
	}
	return tempmultiply;
}

void diffusionmodule(uint8_t interarray[])
{
	uint8_t tem = 0, add_tem[16],mul_inv_tem[16];//去除掩码用
	add_tem[0] = add_mask[0];
	mul_inv_tem[15] = mul_mask_2;
	for (uint8_t i = 0; i < 16; i++)//为加法增加掩码
	{
		intermediate[i] ^= add_mask[i] ;
	}
	for (uint8_t i=0;i<16;i++)
	{
		intermediate[i]	^= s_mask_2;
	}
	for (uint8_t i = 1; i < 16; i++)//加法扩散（正向）
	{
		intermediate[i] ^= intermediate[i - 1];
		add_tem[i] = add_mask[i] ^ add_tem[i - 1];
	}
	for (uint8_t i = 0; i < 16; i++)//将加法掩码转化为乘法掩码
	{
		add_tem[i] ^= mul_mask_1;
		intermediate[i] ^= add_tem[i];
	}
	//对乘法掩码
	uint8_t mul_temp = multiply(mul_mask_1, mul_mask_2);
	for (uint8_t i = 0; i < 16; i++)
	{
		intermediate[i] = multiply(intermediate[i], mul_mask_2);
		intermediate[i] ^= mul_temp;
	}
	for (uint8_t i = 15; i > 0; i--)//乘法扩散（反向）
	{
		if (intermediate[i] == 0)
		{
			tem = multiply(intermediate[i - 1], intermediate[i - 1]);
			mul_inv_tem[i - 1] = mul_mask_2;
		}
		else
		{
			intermediate[i - 1] = multiply(intermediate[i], intermediate[i - 1]);
			mul_inv_tem[i - 1] = multiply(mul_mask_2, mul_inv_tem[i]);
		}
	}

	for (uint8_t i = 0; i < 16; i++)
	{
		intermediate[i] ^= multiply(s_mask_1, mul_inv_tem[i]);
		intermediate[i] = multiply(intermediate[i], inv[mul_inv_tem[i]]);
	}
}
//****************************猫映射*****************************//
void catmap(uint8_t origin[], uint8_t count, uint8_t a, uint8_t b)//a,b:猫映射系数
{
	uint8_t dest[16];//目标数组
	//uint8_t orix = 0, oriy = 0, desx = 0, desy = 0;//origin x,y  dest x,y
	while (count>0)
	{
		for (uint8_t index = 0; index<16; index++)
		{
			switch (index)
			{
				case 0:dest[index] = origin[0]; break;
				case 1:dest[index] = origin[14]; break;
				case 2:dest[index] = origin[8]; break;
				case 3:dest[index] = origin[6]; break;
				case 4:dest[index] = origin[7]; break;
				case 5:dest[index] = origin[1]; break;
				case 6:dest[index] = origin[15]; break;
				case 7:dest[index] = origin[9]; break;
				case 8:dest[index] = origin[10]; break;
				case 9:dest[index] = origin[4]; break;
				case 10:dest[index] = origin[2]; break;
				case 11:dest[index] = origin[12]; break;
				case 12:dest[index] = origin[13]; break;
				case 13:dest[index] = origin[11]; break;
				case 14:dest[index] = origin[5]; break;
				case 15:dest[index] = origin[3]; break;
			}
		}
		for (uint8_t index = 0; index < 16; index++)
		{
			origin[index] = dest[index];
		}
		count--;
	}
}

//**************************帐篷映射模块********************************//
float tentn(float xn, float a)
{
	if (xn < a)
	xn = xn / a;
	else
	xn = (1 - xn) / (1 - a);
	return xn;
}
#endif