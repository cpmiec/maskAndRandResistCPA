///*
 //* maskedChaoticEnc.c
 //* 加入随机掩码和随机化操作防止旁路攻击
 //* Created: 2018/3/26 20:58:51
 //*  Author: Dell
 //*/ 
//#include <asf.h>
//#include "maskedChaoticEnc.h"
//#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//创建触发引脚
//
//void sendUint16(uint16_t value16);//通过串口返回一个uint16类型的数据
//
//uint8_t intermediate[16];
//
//void encInit( void )
//{
	//roundKeyGen((float)0.5987, RDKey);
//}
//void maskEnc(uint8_t ciphertext[], uint8_t plaintext[])
//{
	//for (uint8_t i = 0; i < 16; i++)
		//intermediate[i] = plaintext[i];
//
	//////////////////////////////////////////////////////////////////////////////////////
	//mask_gen(seed);//掩码生成
	//cons_sbox(s_mask_1, s_mask_2);//生成新sbox
	//ioport_set_pin_high(TRIGGER);//置高 PA0，触发能耗统计
	//mask_all(intermediate, s_mask_1);//
	//
	//for (uint8_t i = 0; i < ROUND; i++)
	//{
		//addroundkey(intermediate, RDKey + 16 * i);//i是指轮数，RDKey+16*i是指选择哪一轮轮密钥//
		//getboxvalue(intermediate, msbox);//
		//diffusionmodule(intermediate);
		//catmap(intermediate, 1, 1, 1);
	//}
	//mask_all(intermediate,s_mask_1);
//
	//ioport_set_pin_low(TRIGGER);//置零 PA0，触发能耗统计停止
	//
	//for (uint8_t i = 0; i < 16; i++)
		//ciphertext[i] = intermediate[i];
//}
//
////**************************Round Key Gen*****************************//
//void roundKeyGen(float x0, uint8_t randnum[])//num指丢弃前多少个值
//{
	//float xn = x0; float a;
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//a = (float)0.51 + (float)key[i] / 1000;
		//for (uint8_t j = 0; j < 20; j++)
		//{
			//xn = tentn(xn, a);
		//}
	//}
	//
	//for (uint8_t i = 0; i < 100; i++)
	//{
		//xn=tentn(xn,a);
	//}
	//
	//for (uint8_t i = 0; i < 16 * ROUND; i++)
	//{
		//xn = tentn(xn, a);
		//randnum[i] = (uint8_t)(xn * 256);
	//}
	//seed = tentn(xn, a);
//}
//
////通过Hash函数生成掩码，x0为Hash函数的初始值，a为参数//
//void mask_gen(float x0)//生成掩码
//{
	//float a;
	//float xn = x0;
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//a = (float)0.51 + (float)0.001*intermediate[i];
		//for (uint8_t j = 0; j < 10; j++)
		//{
			//xn = tentn(xn, a);
		//}
	//}
	//xn = tentn(xn, a);
	//s_mask_1 = (uint8_t)(255 * xn);
	//xn = tentn(xn, a);
	//s_mask_2 = (uint8_t)(255 * xn);
//
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//xn = tentn(xn, a);
		//add_mask[i] = (uint8_t)(255*xn) ;
	//}
	//xn = tentn(xn, a);
	//mul_mask_1 = (uint8_t)(255*xn);
	//do //generate the non-zero value used for mul-mask
	//{
		//xn = tentn(xn, a);
	//} while ((mul_mask_2 = (uint8_t)(255*xn))==0);
	//genDiffNum(xn,a,16,seqCtrl);
//}
//
//void genDiffNum(float xn,float a,uint8_t valueRange, uint8_t randSeq[])//generate 16 different values between 0-valueRange-1
//{
	//
	//uint8_t nonZeroCount=0, randIndex=0, randTem=0;
	//uint8_t *randFlag;
	//randFlag=(uint8_t*)malloc(sizeof(uint8_t)*valueRange);
	//for (uint8_t i=0;i<16;i++)
	//{
		//randFlag[i]=0;
	//}
	//while(nonZeroCount<16)//generate 16 different values.
	//{
		//for (uint8_t i=0;i<2;i++)
		//{
			//xn = tentn(xn, a);
		//}
			//
		//randTem=((uint8_t)(255*xn))%valueRange;
		//if (randFlag[randTem]==0)
		//{
			//randSeq[randIndex]=randTem;
			//randFlag[randTem]=1;
			//randIndex++;
			//}else{
			//xn=(float)(0.9)*xn+0.05;
		//}
		//
		////check out whether all the values are generated.	
		//nonZeroCount=0;
		//for (uint8_t i = 0; i < valueRange ; i++)
		//{
			//nonZeroCount+=randFlag[i];
		//}
	//}
	//free(randFlag);
	//randFlag=NULL;
//}
//
////**************************构建新的sbox**************************//
//void cons_sbox(uint8_t mask_in, uint8_t mask_out)//construct_sbox构造 S-box
//{
	//for (int i = 0; i < 256; i++)
	//msbox[i^mask_in] = sbox[i] ^ mask_out;
//}
////*************************对数组的全体元素使用mask进行掩码*********//
//void mask_all(uint8_t arr[], uint8_t mask)//对数组的全体使用mask进行掩码
//{
	//for (uint8_t i = 0; i < 16; i++)
	//arr[i] ^= mask;
//}
//
////**************************Add Round Key*****************************//
//void addroundkey(uint8_t *interarray, uint8_t *roundkey)//
//{
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//interarray[seqCtrl[i]]^=roundkey[seqCtrl[i]];
	//}
//}
//
////**************************S-box变换********************************//
//void getboxvalue(uint8_t interarray[], uint8_t box[])//进行S-box正变换或者反变换
//{
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//interarray[seqCtrl[i]] = box[interarray[seqCtrl[i]]];
	//}
//}
////*************************扩散环节**********************************//
//unsigned char XTIME(unsigned char x)
//{
	//return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
//}
//
//unsigned char multiply(unsigned char a, unsigned char b)
//{
	//unsigned char temp[8] = { a };
	//unsigned char tempmultiply = 0x00;
	//for (int i = 1; i < 8; i++)
	//{
		//temp[i] = XTIME(temp[i - 1]);
	//}
	//tempmultiply = (b & 0x01)*a;
	//for (int i = 1; i < 8; i++)
	//{
		//tempmultiply ^= (((b >> i) & 0x01)*temp[i]);
	//}
	//return tempmultiply;
//}
//
//void diffusionmodule(uint8_t interarray[])
//{
	//uint8_t tem = 0, add_tem[16],mul_inv_tem[16];//去除掩码用
	//add_tem[0] = add_mask[0];
	//mul_inv_tem[15] = mul_mask_2;
	//for (uint8_t i = 0; i < 16; i++)//为加法增加掩码
	//{
		//intermediate[i] ^= add_mask[i] ;
	//}
	//for (uint8_t i=0;i<16;i++)
	//{
		//intermediate[i]	^= s_mask_2;
	//}
	//for (uint8_t i = 1; i < 16; i++)//加法扩散（正向）
	//{
		//intermediate[i] ^= intermediate[i - 1];
		//add_tem[i] = add_mask[i] ^ add_tem[i - 1];
	//}
	//for (uint8_t i = 0; i < 16; i++)//将加法掩码转化为乘法掩码
	//{
		//add_tem[i] ^= mul_mask_1;
		//intermediate[i] ^= add_tem[i];
	//}
	////对乘法掩码
	//uint8_t mul_temp = multiply(mul_mask_1, mul_mask_2);
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//intermediate[i] = multiply(intermediate[i], mul_mask_2);
		//intermediate[i] ^= mul_temp;
	//}
	//for (uint8_t i = 15; i > 0; i--)//乘法扩散（反向）
	//{
		//if (intermediate[i] == 0)
		//{
			//tem = multiply(intermediate[i - 1], intermediate[i - 1]);
			//mul_inv_tem[i - 1] = mul_mask_2;
		//}
		//else
		//{
			//intermediate[i - 1] = multiply(intermediate[i], intermediate[i - 1]);
			//mul_inv_tem[i - 1] = multiply(mul_mask_2, mul_inv_tem[i]);
		//}
	//}
//
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//intermediate[i] ^= multiply(s_mask_1, mul_inv_tem[i]);
		//intermediate[i] = multiply(intermediate[i], inv[mul_inv_tem[i]]);
	//}
//}
////****************************猫映射*****************************//
//void catmap(uint8_t origin[], uint8_t count, uint8_t a, uint8_t b)//a,b:猫映射系数
//{
	//uint8_t dest[16];//目标数组
	////uint8_t orix = 0, oriy = 0, desx = 0, desy = 0;//origin x,y  dest x,y
	//while (count>0)
	//{
		//for (uint8_t index = 0; index<16; index++)
		//{
			//switch (index)
			//{
				//case 0:dest[index] = origin[0]; break;
				//case 1:dest[index] = origin[14]; break;
				//case 2:dest[index] = origin[8]; break;
				//case 3:dest[index] = origin[6]; break;
				//case 4:dest[index] = origin[7]; break;
				//case 5:dest[index] = origin[1]; break;
				//case 6:dest[index] = origin[15]; break;
				//case 7:dest[index] = origin[9]; break;
				//case 8:dest[index] = origin[10]; break;
				//case 9:dest[index] = origin[4]; break;
				//case 10:dest[index] = origin[2]; break;
				//case 11:dest[index] = origin[12]; break;
				//case 12:dest[index] = origin[13]; break;
				//case 13:dest[index] = origin[11]; break;
				//case 14:dest[index] = origin[5]; break;
				//case 15:dest[index] = origin[3]; break;
			//}
		//}
		//for (uint8_t index = 0; index < 16; index++)
		//{
			//origin[index] = dest[index];
		//}
		//count--;
	//}
//}
//
////**************************帐篷映射模块********************************//
//float tentn(float xn, float a)
//{
	//if (xn < a)
	//xn = xn / a;
	//else
	//xn = (1 - xn) / (1 - a);
	//return xn;
//}