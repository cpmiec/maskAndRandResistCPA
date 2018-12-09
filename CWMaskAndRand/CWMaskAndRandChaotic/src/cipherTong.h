#ifndef __CHAOTICCIPHER_H__
#define __CHAOTICCIPHER_H__

#include<stdint.h>
uint16_t pBox(uint16_t x);
//uint8_t cubic8(uint8_t x);
uint32_t cubic32(uint32_t x);
uint32_t logistic(uint32_t x);
uint32_t linearCongruence(uint32_t x);
void seqGen(uint32_t x, uint32_t* outArr);

void roundKeyGen(uint8_t *roundKey1, uint8_t *roundKey2);//…˙≥…¬÷√‹‘ø
void encTxj(uint8_t* plaintext, uint8_t* ciphertext);
void decryption(uint8_t* plaintext, uint8_t* ciphertext, uint8_t* enKey1, uint8_t* enKey2);

#endif // !__CHAOTICCIPHER_H__

