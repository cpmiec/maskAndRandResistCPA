///*
 //* maskedChaoticEnc.c
 //*
 //* Created: 2018/3/26 20:58:51
 //*  Author: Dell
 //*/ 
//#include <asf.h>
//#include "chaoticEnc.h"
//#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//������������
//
//uint8_t intermediate[16];
//
//void encInit(void)
//{
	//roundKeyGen((float)0.5987, RDKey);
//}
//void chaoticEnc(uint8_t ciphertext[], uint8_t plaintext[])
//{
	//for (uint8_t i = 0; i < 16; i++)
		//intermediate[i] = plaintext[i];
//
	//ioport_set_pin_high(TRIGGER);//�ø� PA0�������ܺ�ͳ��
	//////////////////////////////////////////////////////////////////////////////////////
	//for (uint8_t i = 0; i < ROUND; i++)
	//{		
		//addroundkey(intermediate, RDKey + 16 * i);//i��ָ������RDKey+16*i��ָѡ����һ������Կ//
		//getboxvalue(intermediate, sbox);//
		//diffusionmodule(intermediate);
		//catmap(intermediate, 1, 1, 1);
	//}
	//
	//ioport_set_pin_low(TRIGGER);//���� PA0;
	//for (uint8_t i = 0; i < 16; i++)
		//ciphertext[i] = intermediate[i];
//}
//
////**************************Round Key Gen*****************************//
//void roundKeyGen(float x0, uint8_t randnum[])//numָ����ǰ���ٸ�ֵ
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
	//for (uint8_t i = 0; i < 16 * ROUND; i++)
	//{
		//xn = tentn(xn, a);
		//randnum[i] = (uint8_t)(xn * 256);
	//}
	//seed = tentn(xn, a);
//}
//
////**************************Add Round Key*****************************//
//void addroundkey(uint8_t	*interarray, uint8_t *roundkey)//
//{
	//for (uint8_t index = 0; index < 16; index++)
	//{
		//*(interarray + index) = (*(interarray + index)) ^ (*(roundkey + index));
	//}
//}
//
////**************************S-box�任********************************//
//void getboxvalue(uint8_t interarray[], uint8_t box[])//����S-box���任���߷��任
//{
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//interarray[i] = box[interarray[i]];
	//}
//}
//
////****************************��ɢģ��**********************************//
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
//void diffusionmodule(uint8_t interarray[])
//{
	//for (uint8_t i = 1; i < 16; i++)//����
	//{
		//interarray[i] ^= interarray[i - 1];
	//}
	//for (uint8_t i = 15; i > 0; i--)//����
	//{
		//if (interarray[i] == 0) continue;
		//interarray[i - 1] = multiply(interarray[i], interarray[i - 1]);
	//}
//}
//
////****************************èӳ��*****************************//
//void catmap(uint8_t origin[], uint8_t count, uint8_t a, uint8_t b)//a,b:èӳ��ϵ��
//{
	//uint8_t dest[16];//Ŀ������
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
////**************************����ӳ��ģ��********************************//
//float tentn(float xn, float a)
//{
	//if (xn < a)
	//xn = xn / a;
	//else
	//xn = (1 - xn) / (1 - a);
	//return xn;
//}