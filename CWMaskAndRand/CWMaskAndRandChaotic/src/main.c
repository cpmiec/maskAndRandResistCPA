/**
 * \file
 *
 * \使用ASF框架构建Chipwhisperer加密系统框架
	能耗统计均触发及结束均放在加密程序中
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
#define USART_T IOPORT_CREATE_PIN(PORTC,3)//创建串口发送引脚
#define USART_R IOPORT_CREATE_PIN(PORTC,2)//创建串口接收引脚
#define TRIGGER IOPORT_CREATE_PIN(PORTA,0)//创建触发引脚
#define LED9 IOPORT_CREATE_PIN(PORTA,5)
#define LED10 IOPORT_CREATE_PIN(PORTA,6)

#define KEY_LENGTH 16
#define BUFLEN KEY_LENGTH*4

uint8_t memory[BUFLEN];
char asciibuf[BUFLEN];
uint8_t pt[KEY_LENGTH];//明文
uint8_t key[KEY_LENGTH];//密钥

void CWPlatInit(void);
void sendUint16(uint16_t value16);//通过串口返回一个uint16类型的数据
void sendUint8(uint8_t value8);//通过串口返回一个uint8类型的数据

void encryptionInit(void);
void encryption(uint8_t ciphertext[], uint8_t plaintext[]);

int main (void)
{
	uint16_t timeCost=0;
	//初始化平台
	CWPlatInit();
	
	//加密程序
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
				//**************进行加密**************//
				tc_write_count(&TCC0,0);//清零计数器
				
				encryptionInit();//加密准备工作
				//ioport_set_pin_high(TRIGGER);//置高 PA0，触发能耗统计，
				
				encryption(pt,pt);
				
				timeCost=tc_read_count(&TCC0);//定时结束
				//ioport_set_pin_low(TRIGGER);//置零 PA0，结束能耗统计
				
				//***********将密文转化为字符*********//
				hex_print(pt,16,asciibuf);
				//*************串口发送密文***********//
				usart_serial_putchar(USART_SERIAL,'r');
				for(uint8_t i=0;i<32;i++)
				{
					usart_serial_putchar(USART_SERIAL,asciibuf[i]);
				}
				usart_serial_putchar(USART_SERIAL,'\n');
				
				sendUint16(timeCost);//返回时间消耗
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
	//时钟初始化,使用外部时钟，7370000 hz
	sysclk_init();
	
	//初始化IO口
	ioport_init(); 
	//初始化串口
	ioport_set_pin_dir(USART_T,IOPORT_DIR_OUTPUT);//确定数据方向
	ioport_set_pin_dir(USART_R,IOPORT_DIR_INPUT);//确定数据方向
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
	//定时器初始化设置
	tc_enable(&TCC0);
	tc_set_wgm(&TCC0,TC_WG_NORMAL);
	tc_set_direction(&TCC0,TC_UP);
	tc_write_clock_source(&TCC0,TC_CLKSEL_DIV4_gc);//开始计时
}
void sendUint16(uint16_t value16)//通过串口返回一个uint16类型的数据
{
	uint8_t valueBuff[5];
	valueBuff[0]=value16/10000;valueBuff[1]=(value16/1000)%10;valueBuff[2]=(value16/100)%10;valueBuff[3]=(value16/10)%10;valueBuff[4]=(value16)%10;
	for (uint8_t i=0;i<5;i++)
	{
		usart_serial_putchar(USART_SERIAL,48+valueBuff[i]);//
	}
	usart_serial_putchar(USART_SERIAL,'\n');
}
void sendUint8(uint8_t value8)//通过串口返回一个8bit寄存器的状态
{
	uint8_t bitMask=128;
	for (uint8_t i=0;i<8;i++)
	{
		(value8 & bitMask)?usart_serial_putchar(USART_SERIAL,49):usart_serial_putchar(USART_SERIAL,48);
		bitMask=bitMask>>1;
	}
	usart_serial_putchar(USART_SERIAL,'\n');
}

