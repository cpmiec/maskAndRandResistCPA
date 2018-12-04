/*
 * asciitoint.h
 *
 * Created: 2017/3/23 14:17:12
 *  Author: Dell
 */ 


#ifndef ASCIITOINT_H_
#define ASCIITOINT_H_

	uint8_t* hex_decode(const char *in, int len,uint8_t *out);//将ASCII数据转化为真实的数字
	void hex_print(const uint8_t * in, int len, char *out);//将数字转化为ASCII

#endif /* ASCIITOINT_H_ */