/*
 * ASCIItoInt.c
 *
 * Created: 2017/3/23 14:24:09
 *  Author: Dell
 */ 
#include <stdint-gcc.h>
char hex_lookup[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

uint8_t* hex_decode(const char *in, int len,uint8_t *out)//��ASCII����ת��Ϊ��ʵ������
{
	unsigned int i, t, hn, ln;

	for (t = 0,i = 0; i < len; i+=2,++t)
	{
		hn = in[i] > '9' ? (in[i]|32) - 'a' + 10 : in[i] - '0';//��16����ת��Ϊ10���ƣ����Һ��Դ�Сд���������A��a
		ln = in[i+1] > '9' ? (in[i+1]|32) - 'a' + 10 : in[i+1] - '0';
		out[t] = (hn << 4 ) | ln;
	}
	return out;
}

void hex_print(const uint8_t *in, int len, char *out)//������ת��ΪASCII
{
	unsigned int i,j;
	j=0;
	for (i=0; i < len; i++)
	{
		out[j++] = hex_lookup[in[i] >> 4];
		out[j++] = hex_lookup[in[i] & 0x0F];
	}
	out[j] = 0;
}
