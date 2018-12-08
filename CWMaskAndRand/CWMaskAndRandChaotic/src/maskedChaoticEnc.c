///*
 //* maskedChaoticEnc.c
 //* �����������������������ֹ��·����
 //* Created: 2018/3/26 20:58:51
 //*  Author: Dell
 //*/ 
//#include <asf.h>
//#include "maskedChaoticEnc.h"
//#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//������������
//
//void sendUint16(uint16_t value16);//ͨ�����ڷ���һ��uint16���͵�����
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
	//mask_gen(seed);//��������
	//cons_sbox(s_mask_1, s_mask_2);//������sbox
	//ioport_set_pin_high(TRIGGER);//�ø� PA0�������ܺ�ͳ��
	//mask_all(intermediate, s_mask_1);//
	//
	//for (uint8_t i = 0; i < ROUND; i++)
	//{
		//addroundkey(intermediate, RDKey + 16 * i);//i��ָ������RDKey+16*i��ָѡ����һ������Կ//
		//getboxvalue(intermediate, msbox);//
		//diffusionmodule(intermediate);
		//catmap(intermediate, 1, 1, 1);
	//}
	//mask_all(intermediate,s_mask_1);
//
	//ioport_set_pin_low(TRIGGER);//���� PA0�������ܺ�ͳ��ֹͣ
	//
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
////ͨ��Hash�����������룬x0ΪHash�����ĳ�ʼֵ��aΪ����//
//void mask_gen(float x0)//��������
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
////**************************�����µ�sbox**************************//
//void cons_sbox(uint8_t mask_in, uint8_t mask_out)//construct_sbox���� S-box
//{
	//for (int i = 0; i < 256; i++)
	//msbox[i^mask_in] = sbox[i] ^ mask_out;
//}
////*************************�������ȫ��Ԫ��ʹ��mask��������*********//
//void mask_all(uint8_t arr[], uint8_t mask)//�������ȫ��ʹ��mask��������
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
////**************************S-box�任********************************//
//void getboxvalue(uint8_t interarray[], uint8_t box[])//����S-box���任���߷��任
//{
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//interarray[seqCtrl[i]] = box[interarray[seqCtrl[i]]];
	//}
//}
////*************************��ɢ����**********************************//
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
	//uint8_t tem = 0, add_tem[16],mul_inv_tem[16];//ȥ��������
	//add_tem[0] = add_mask[0];
	//mul_inv_tem[15] = mul_mask_2;
	//for (uint8_t i = 0; i < 16; i++)//Ϊ�ӷ���������
	//{
		//intermediate[i] ^= add_mask[i] ;
	//}
	//for (uint8_t i=0;i<16;i++)
	//{
		//intermediate[i]	^= s_mask_2;
	//}
	//for (uint8_t i = 1; i < 16; i++)//�ӷ���ɢ������
	//{
		//intermediate[i] ^= intermediate[i - 1];
		//add_tem[i] = add_mask[i] ^ add_tem[i - 1];
	//}
	//for (uint8_t i = 0; i < 16; i++)//���ӷ�����ת��Ϊ�˷�����
	//{
		//add_tem[i] ^= mul_mask_1;
		//intermediate[i] ^= add_tem[i];
	//}
	////�Գ˷�����
	//uint8_t mul_temp = multiply(mul_mask_1, mul_mask_2);
	//for (uint8_t i = 0; i < 16; i++)
	//{
		//intermediate[i] = multiply(intermediate[i], mul_mask_2);
		//intermediate[i] ^= mul_temp;
	//}
	//for (uint8_t i = 15; i > 0; i--)//�˷���ɢ������
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