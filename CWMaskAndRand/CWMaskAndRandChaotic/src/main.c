/**
 * \file
 *
 * \ʹ��ASF��ܹ���Chipwhisperer����ϵͳ���
	�ܺ�ͳ�ƾ����������������ڼ��ܳ�����
 *
 */

/**
 * \mainpage User Application template doxygen documentation
 *
 * \par Empty user application template
 *
 * Bare minimum empty user application template
 *
 * \par Content
 *
 * -# Include the ASF header files (through asf.h)
 * -# "Insert system clock initialization code here" comment
 * -# Minimal main function that starts with a call to board_init()
 * -# "Insert application code here" comment
 *
 */

/*
 * Include header files for all drivers that have been imported from
 * Atmel Software Framework (ASF).
 */
/*
 * Support and FAQ: visit <a href="http://www.atmel.com/design-support/">Atmel Support</a>
 */
#include <asf.h>
#include "char_int.h"
#define USART_T IOPORT_CREATE_PIN(PORTC,3)//�������ڷ�������
#define USART_R IOPORT_CREATE_PIN(PORTC,2)//�������ڽ�������
#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//������������
#define LED9 IOPORT_CREATE_PIN(PORTA,5)
#define LED10 IOPORT_CREATE_PIN(PORTA,6)

#define KEY_LENGTH 16
#define BUFLEN KEY_LENGTH*4

uint8_t memory[BUFLEN];
char asciibuf[BUFLEN];
uint8_t pt[KEY_LENGTH];//����
uint8_t key[KEY_LENGTH];//��Կ

void CWPlatInit(void);
void sendUint16(uint16_t value16);//ͨ�����ڷ���һ��uint16���͵�����
void sendUint8(uint8_t value8);//ͨ�����ڷ���һ��uint8���͵�����

void encryptionInit(void);
void encryption(uint8_t ciphertext[], uint8_t plaintext[]);

int main (void)
{
	uint16_t timeCost=0;
	//��ʼ��ƽ̨
	CWPlatInit();
	
	//���ܳ���
	uint8_t received_byte; 
	uint8_t ptr=0;
	enum statesel{IDLE,KEY,PLAIN}state;
	state=IDLE;
	
	while(1)
	{
		usart_serial_getchar(USART_SERIAL, &received_byte);
		if (received_byte=='x')
		{
			ptr=0;
			state=IDLE;
			continue;
		}
		else if (received_byte=='k')
		{
			ptr=0;
			state=KEY;
			continue;
		}
		else if (received_byte=='p')
		{
			ptr=0;
			state=PLAIN;
			continue;
		}
		else if (state==KEY)
		{
			if ((received_byte=='\n')||(received_byte=='\r'))
			{
				asciibuf[ptr]=0;
				hex_decode(asciibuf,ptr,key);
				state=IDLE;
			}
			else
			{
				asciibuf[ptr++]=received_byte;
			}
		}
		else if (state==PLAIN)
		{
			if ((received_byte=='\n')||(received_byte=='\r'))
			{
				asciibuf[ptr]=0;
				hex_decode(asciibuf,ptr,pt);
				//**************���м���**************//
				tc_write_count(&TCC0,0);//���������
				
				encryptionInit();//����׼������
				//ioport_set_pin_high(TRIGGER);//�ø� PA0�������ܺ�ͳ�ƣ�
				
				encryption(pt,pt);
				
				timeCost=tc_read_count(&TCC0);//��ʱ����
				//ioport_set_pin_low(TRIGGER);//���� PA0�������ܺ�ͳ��
				
				//***********������ת��Ϊ�ַ�*********//
				hex_print(pt,16,asciibuf);
				//*************���ڷ�������***********//
				usart_serial_putchar(USART_SERIAL,'r');
				for(uint8_t i=0;i<32;i++)
				{
					usart_serial_putchar(USART_SERIAL,asciibuf[i]);
				}
				usart_serial_putchar(USART_SERIAL,'\n');
				
				sendUint16(timeCost);//����ʱ������
				sendUint8(CLK.CTRL);
				state=IDLE;
			}
			else
			{
				if (ptr>=BUFLEN)
				{
					state=IDLE;
				}
				else
				{
					asciibuf[ptr++]=received_byte;
				}
			}
		}
	}
	return 1;
}

void CWPlatInit( void )
{
	//ʱ�ӳ�ʼ��,ʹ���ⲿʱ�ӣ�7370000 hz
	sysclk_init();
	
	//��ʼ��IO��
	ioport_init(); 
	//��ʼ������
	ioport_set_pin_dir(USART_T,IOPORT_DIR_OUTPUT);//ȷ�����ݷ���
	ioport_set_pin_dir(USART_R,IOPORT_DIR_INPUT);//ȷ�����ݷ���
	ioport_set_pin_dir(TRIGGER,IOPORT_DIR_OUTPUT);//
	ioport_set_pin_dir(LED9,IOPORT_DIR_OUTPUT);
	ioport_set_pin_low(LED9);
	ioport_set_pin_dir(LED10,IOPORT_DIR_OUTPUT);
	ioport_set_pin_high(LED10);

	static usart_serial_options_t usart_options = {
		.baudrate = USART_SERIAL_BAUDRATE,
		.charlength = USART_SERIAL_CHAR_LENGTH,
		.paritytype = USART_SERIAL_PARITY,
		.stopbits = USART_SERIAL_STOP_BIT
	};
	usart_serial_init(USART_SERIAL, &usart_options);
	//��ʱ����ʼ������
	tc_enable(&TCC0);
	tc_set_wgm(&TCC0,TC_WG_NORMAL);
	tc_set_direction(&TCC0,TC_UP);
	tc_write_clock_source(&TCC0,TC_CLKSEL_DIV4_gc);//��ʼ��ʱ
}
void sendUint16(uint16_t value16)//ͨ�����ڷ���һ��uint16���͵�����
{
	uint8_t valueBuff[5];
	valueBuff[0]=value16/10000;valueBuff[1]=(value16/1000)%10;valueBuff[2]=(value16/100)%10;valueBuff[3]=(value16/10)%10;valueBuff[4]=(value16)%10;
	for (uint8_t i=0;i<5;i++)
	{
		usart_serial_putchar(USART_SERIAL,48+valueBuff[i]);//
	}
	usart_serial_putchar(USART_SERIAL,'\n');
}
void sendUint8(uint8_t value8)//ͨ�����ڷ���һ��8bit�Ĵ�����״̬
{
	uint8_t bitMask=128;
	for (uint8_t i=0;i<8;i++)
	{
		(value8 & bitMask)?usart_serial_putchar(USART_SERIAL,49):usart_serial_putchar(USART_SERIAL,48);
		bitMask=bitMask>>1;
	}
	usart_serial_putchar(USART_SERIAL,'\n');
}

