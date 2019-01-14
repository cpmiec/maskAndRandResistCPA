
/*
 *
 * Virginia Tech
 * Secure Embedded Systems Lab
 *
 * Copyright (C) 2017 Virginia Tech
 *
 * Written in 2017 by Yuan Yao. This masked implementation refers to 
 * https://github.com/ermin-sakic/smartcard-aes-fw.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifdef BYTE_MASK_AES
#include "byte_mask_aes.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

uint8_t roundKey[176];
uint8_t Sbox_masked[256];
uint8_t Mask[10];
uint8_t RoundKey_masked[11][16];
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d);


static uint8_t getSBoxValue(uint8_t num)
{
    return sbox[num];
}




void mixColumns(uint8_t state[16]){

	uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
	uint8_t i, j, col[4], res[4];

	for (j = 0; j < Nb; j++) {
		for (i = 0; i < 4; i++) {
			col[i] = state[Nb*i+j];
		}

		coef_mult(a, col, res);

		for (i = 0; i < 4; i++) {
			state[Nb*i+j] = res[i];
		}
	}
}
void shiftRows(uint8_t state[16]){
	
    uint8_t temp;

	//Row 2
	temp = state[1]; 
	state[1] = state[5]; 
	state[5] = state[9];
        state[9] = state[13]; 
        state[13] = temp;
	//Row 3
	temp = state[10]; 
	state[10] =state[2]; 
	state[2]  = temp;
	temp = state[14]; 
	state[14] = state[6]; 
	state[6] = temp;
	//Row 4
	temp = state[3]; 
	state[3] = state[15]; 
	state[15] = state[11]; 
        state[11] = state[7]; 
        state[7] = temp;
}


void addRoundKey_masked(uint8_t state[16],uint8_t round){

	uint8_t i;
	for(i=0;i<16;i++){
		state[i] ^= RoundKey_masked[round][i];
	}
}

void masked(uint8_t state[16]){
	
	uint8_t i;
	for (i = 0; i < 16; i++) {
		state[i] = Sbox_masked[state[i]];
	}
}

void remask(uint8_t s[16], uint8_t m1, uint8_t m2, uint8_t m3, uint8_t m4, uint8_t m5, uint8_t m6, uint8_t m7, uint8_t m8){

    int i;	
	for(i = 0; i< 4; i++){
		s[0+i*4]	= s[0+i*4] ^ (m1^m5);
		s[1+i*4]	= s[1+i*4] ^ (m2^m6);
		s[2+i*4]	= s[2+i*4] ^ (m3^m7);
		s[3+i*4]	= s[3+i*4] ^ (m4^m8);
	}
}


//PRECALCULATIONS:
//Yuan
void calcMixColMask(){
	
//yuan
/* Normal Mix Columns:
 * [w]      [2  3  1  1]    [a]
 * [x]  =   [1  2  3  1]  * [b]
 * [y]      [1  1  2  3]    [c]
 * [z]      [3  1  1  2]    [d]*/
		
	Mask[6]	=	mul_02[Mask[0]]	^ mul_03[Mask[1]]   ^Mask[2]	^Mask[3];
	Mask[7]	=	Mask[0]	^ mul_02[Mask[1]]	^mul_03[Mask[2]]	^Mask[3];
	Mask[8]	=	Mask[0]	^ Mask[1]	^mul_02[Mask[2]]	^mul_03[Mask[3]];
	Mask[9]	=	mul_03[Mask[0]]	^ Mask[1]	^Mask[2]	^mul_02[Mask[3]];
	
}
void calcSbox_masked(){

	//precalculate the needed Sbox to change from Mask m to Maks m'
	int cnt;
    for(cnt=0;cnt<256;cnt++){
		Sbox_masked[cnt^Mask[4]] = sbox[cnt]^Mask[5];
	}	
}
void init_masked_round_keys(){

	//	2nd-9th RK Mask m' to Mask m1-m4

    int i;
	for(i = 0; i<10;i++){
		remask(RoundKey_masked[i],Mask[6],Mask[7],Mask[8],Mask[9],Mask[4],Mask[4],Mask[4],Mask[4]); 
	}
	
	//1st RK Mask m' to 0
	remask(RoundKey_masked[10],0,0,0,0,Mask[5],Mask[5],Mask[5],Mask[5]); 
}
void copy_key(){
	//copy the right roundkeys to masked key array
	
	uint8_t i,j;
	for(i=0;i<11;i++){
		for(j=0;j<16;j++){
			RoundKey_masked[i][j] = roundKey[i*16+j];
		}
	}
}
void init_masking(){
	copy_key();

	//Calculates: m1',m2',m3',m4'
	calcMixColMask();
	calcSbox_masked(); 
	init_masked_round_keys();
	
}


void subBytes_masked(uint8_t state[16]){

	    uint8_t i;
		for (i = 0; i < 16; i++) {
			state[i] = Sbox_masked[state[i]];
		}
}

/******************************************************************/
//       AES masked encryption                                   //
/******************************************************************/
void aes128(uint8_t* state)
{	

	init_masking();

	remask(state,Mask[6],Mask[7],Mask[8],Mask[9],0,0,0,0);

        addRoundKey_masked(state, 0);  

	uint8_t i;
    for (i = 1; i <10; i++) {
			subBytes_masked(state);
			shiftRows(state);

		remask(state,Mask[0],Mask[1],Mask[2],Mask[3],Mask[5],Mask[5],Mask[5],Mask[5]); 
		mixColumns(state);
        	addRoundKey_masked(state, i);
    }
// shuffling

  // if(rand()%2 == 1){
			//subBytes_masked_rand(state,hiding_sequence);
			subBytes_masked(state);
			shiftRows(state);
	//	}
//		else{
//			shiftRows(state);
//		        subBytes_masked_rand(state,hiding_sequence);
//			subBytes_masked(state);
//		}

    
    addRoundKey_masked(state, 10);
	
}
#endif
