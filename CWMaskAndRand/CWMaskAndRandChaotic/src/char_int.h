/*
 * asciitoint.h
 *
 * Created: 2017/3/23 14:17:12
 *  Author: Dell
 */ 


#ifndef ASCIITOINT_H_
#define ASCIITOINT_H_

	uint8_t* hex_decode(const char *in, int len,uint8_t *out);//��ASCII����ת��Ϊ��ʵ������
	void hex_print(const uint8_t * in, int len, char *out);//������ת��ΪASCII

#endif /* ASCIITOINT_H_ */