/*
 *	BOOT LEDS
 *	AUTHOR: Patrik Pfaffenbauer
 *	DATE: 04-04-2013
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>	
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>

#include <linux/leds.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <asm/gpio.h>
#include <linux/slab.h>
#include <linux/semaphore.h>
#include "leds.h"

#define GPIO_LED1_ROT           (2*32 + 25)     /* GPIO_2_25 - LCD_AC_BIAS_EN */
#define GPIO_LED1_GRUEN         (1*32 + 19)     /* GPIO_1_19 - GPMC_A3 */
#define GPIO_LED2_ROT           (2*32 + 23)     /* GPIO_2_23 - LCD_HSYNC */
#define GPIO_LED2_GRUEN         (1*32 + 17)     /* GPIO_1_17 - GPMC_A1 */
#define GPIO_LED3_ROT           (2*32 +  0)     /* GPIO_2_0  - GPMC_CSN3 */
#define GPIO_LED3_GRUEN         (2*32 + 24)     /* GPIO_2_24 - LCD_PCLK */

#define DEV_NAME "lc1"

static dev_t first;
static struct cdev c_dev;
static struct class *cl;
static char state;
static int openCount = 0;

static int request_led_gpios(void);
static int free_led_gpios(void);
static void init_boot_leds(void);
static void init_boot_led(int i);

struct timer_data {
        struct timer_list timer;
	int brightness;
        int led_info;
	int running;
};

enum led_color {
	LED_COLOR_OFF = 0,
	LED_GREEN,
	LED_RED,
	LED_ORANGE
};

enum led_operation {
	LED_BLINK = 0,
	LED_ON
};

struct gpio_leds {
	enum led_color color;
	enum led_operation operation;
	unsigned gpio_red;
	unsigned gpio_green;
	struct timer_data* timer;
};

static struct gpio_leds leds[] = {
	{
		.color = LED_ORANGE,
		.operation = LED_BLINK,
		.gpio_red = GPIO_LED1_ROT,
		.gpio_green = GPIO_LED1_GRUEN,
		.timer = 0
	},	{
		.color = LED_ORANGE,
		.operation = LED_ON,
		.gpio_red = GPIO_LED2_ROT,
		.gpio_green = GPIO_LED2_GRUEN,
		.timer = 0
	},	{
		.color = LED_ORANGE,
		.operation = LED_ON,
		.gpio_red = GPIO_LED3_ROT,
		.gpio_green = GPIO_LED3_GRUEN,
		.timer = 0
	}
};

static int request_led_gpios(void) {
	unsigned char gpioErr = 0;
	if (openCount > 0)
		return 0;

	gpioErr |= gpio_request(GPIO_LED1_ROT, "led1_red") ? 0x01 : 0x00;
	gpioErr |= gpio_request(GPIO_LED1_GRUEN, "led1_green") ? 0x02 : 0x00;
	gpioErr |= gpio_request(GPIO_LED2_ROT, "led2_red") ? 0x04 : 0x00;
	gpioErr |= gpio_request(GPIO_LED2_GRUEN, "led2_green") ? 0x08 : 0x00;
	gpioErr |= gpio_request(GPIO_LED3_ROT, "led3_red") ? 0x10 : 0x00;
	gpioErr |= gpio_request(GPIO_LED3_GRUEN, "led3_green") ? 0x20 : 0x00;

	if (!gpioErr) {
		gpioErr |= gpio_direction_output(GPIO_LED1_ROT, 1) ? 0x40 : 0x00;
		gpioErr |= gpio_direction_output(GPIO_LED1_GRUEN, 1) ? 0x40 : 0x00;
		gpioErr |= gpio_direction_output(GPIO_LED2_ROT, 1) ? 0x40 : 0x00;
		gpioErr |= gpio_direction_output(GPIO_LED2_GRUEN, 1) ? 0x40 : 0x00;
		gpioErr |= gpio_direction_output(GPIO_LED3_ROT, 1) ? 0x40 : 0x00;
		gpioErr |= gpio_direction_output(GPIO_LED3_GRUEN, 1) ? 0x40 : 0x00;
	}

	if (gpioErr) {
		if (!(gpioErr & 0x01)) gpio_free(GPIO_LED1_ROT);
		if (!(gpioErr & 0x02)) gpio_free(GPIO_LED1_GRUEN);
		if (!(gpioErr & 0x04)) gpio_free(GPIO_LED2_ROT);
		if (!(gpioErr & 0x08)) gpio_free(GPIO_LED2_GRUEN);
		if (!(gpioErr & 0x10)) gpio_free(GPIO_LED3_ROT);
		if (!(gpioErr & 0x20)) gpio_free(GPIO_LED3_GRUEN);
		return -1;
	}

	++openCount;
	return 0;
};

static int free_led_gpios(void) {
	if (!openCount)
		return -1;

	gpio_free(GPIO_LED1_ROT);
	gpio_free(GPIO_LED1_GRUEN);
	gpio_free(GPIO_LED2_ROT);
	gpio_free(GPIO_LED2_GRUEN);
	gpio_free(GPIO_LED3_ROT);
	gpio_free(GPIO_LED3_GRUEN);

	--openCount;
        return 0;
};

static int device_open(struct inode* inode, struct file *file) {
	if (!openCount)
		return -EINVAL;

	return 0;
};

static int device_release(struct inode *inode, struct file *file) {
        return 0;
};

static ssize_t device_read(struct file *filep, char* buffer, size_t length, loff_t* offset) {
	return 0;
};

static ssize_t device_write(struct file *filep, const char *buffer, size_t length, loff_t *offset) {
    
	int ledNr = -1;
	enum led_operation operation;
	enum led_color color;
		
	if(length >= 6)
	{
		char newState[6];
		copy_from_user(&newState, buffer, 6);
		
		ledNr = (newState[0] - 48);
		operation = (enum led_operation)(newState[2] - 48);
		color = (enum led_color)(newState[4] - 48);
		//printk(KERN_DEBUG "Changing led %d %d %d", ledNr, operation, color);
		
		if((ledNr >= 0 && ledNr <= 2) && (operation >= 0 && operation <= 1) && (color >= 0 && color <= 3))
		{
			leds[ledNr].operation = operation;
			leds[ledNr].color = color;

			init_boot_led(ledNr);
		}
		
	}
	return length;
};

static struct file_operations fops = {
        .read = device_read,
        .write = device_write,
        .open = device_open,
        .release = device_release
};

static void timer_func(unsigned long data) 
{	
	int is_in_int = 0;
	struct timer_data *timer = (struct timer_data*)data;;

	if(!timer) {
		//printk(KERN_DEBUG "returing timer_func -> timer is not set");
		return;
	}

	if(in_interrupt()) {
		//printk(KERN_DEBUG "disable interrupts");
		local_irq_disable();
		is_in_int = 1;
	}
	

	switch(leds[timer->led_info].color)
	{
		case LED_ORANGE:
			 gpio_set_value(leds[timer->led_info].gpio_red, timer->brightness);
			 gpio_set_value(leds[timer->led_info].gpio_green, timer->brightness);
			 //printk(KERN_DEBUG "set ledi %d orange %d", timer->led_info, timer->brightness);
		break;
		case LED_RED:
			 gpio_set_value(leds[timer->led_info].gpio_red, timer->brightness);
			 gpio_set_value(leds[timer->led_info].gpio_green, 1);
			 //printk(KERN_DEBUG "set led %d red %d", timer->led_info, timer->brightness);
		break;
		case LED_GREEN:
			gpio_set_value(leds[timer->led_info].gpio_green, timer->brightness);
			gpio_set_value(leds[timer->led_info].gpio_red, 1);
			//printk(KERN_DEBUG "set led %d green %d", timer->led_info, timer->brightness);
		break;
		case LED_COLOR_OFF:
			 gpio_set_value(leds[timer->led_info].gpio_red, 1);
			 gpio_set_value(leds[timer->led_info].gpio_green, 1);
			 //printk(KERN_DEBUG "set led %d off %d", timer->led_info, timer->brightness);
		break;
	}


	if(leds[timer->led_info].operation == LED_BLINK)
	{
		if(timer->running) {
			mod_timer(&timer->timer, jiffies + 10);
			timer->brightness = !timer->brightness;
		}
	}

	if(is_in_int) {
                //printk(KERN_DEBUG "enable interrupts");
                local_irq_enable();
        }
};

void init_boot_leds(void) {
	int i;
	state = 1;

	for(i = 0; i < ARRAY_SIZE(leds); i++) {
		struct timer_data *timer = kzalloc(sizeof(struct timer_data), GFP_KERNEL);
		leds[i].timer = timer;
		
		timer->running = 1;
		timer->led_info = i;
		timer->brightness = 0;
		timer->timer.function = timer_func;
		timer->timer.data = (unsigned long)timer;

		init_timer(&timer->timer);
		add_timer(&timer->timer);

		init_boot_led(i);
	}
};

void init_boot_led(int i) {

	struct timer_data *timer = leds[i].timer;

	if(leds[i].timer) {
//		mod_timer(&timer->timer, -1);
		timer->running = 0;
	} 
	
	if(leds[i].color == LED_COLOR_OFF) {
		gpio_set_value(leds[i].gpio_red, 1);
		gpio_set_value(leds[i].gpio_green, 1);
		timer->running = 0;
		timer->brightness = 1;
		//printk(KERN_DEBUG "set led %d off", timer->led_info);
	}
	else {
		if(!timer)
			return;
		timer->brightness=0;
		if(leds[timer->led_info].operation == LED_BLINK)
			timer->running = 1;
		timer_func((unsigned long)timer);
	}
};

static int init_device(void) {
	if (request_led_gpios())
		return -1;

	if(alloc_chrdev_region(&first, 0, 1, DEV_NAME) < 0){
		free_led_gpios();
		return -1;
	}

	if((cl = class_create(THIS_MODULE, DEV_NAME)) == NULL) {
		unregister_chrdev_region(first, 1);
		free_led_gpios();
		return -1;
	}

	if(device_create(cl, NULL, first, NULL, DEV_NAME) == NULL) {
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		free_led_gpios();
		return -1;
	}

	cdev_init(&c_dev, &fops);
	if(cdev_add(&c_dev, first, 1) == -1) {
		device_destroy(cl, first);
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		free_led_gpios();
		return -1;
	}

	return 0;
}


static int __init start_module(void) {
	state = -1;

	if(init_device() != 0)
	{
		printk(KERN_INFO "Could not load led-control module -> char device could not be created");
		return -1;
	}
	init_boot_leds();
	printk(KERN_INFO "Loading led-control module (c) BeKa-Software 2012 - 2015");
	printk(KERN_INFO "Original written by Patrik Pfaffenbauer (www.github.com/p3root)");
	return 0;
};

static void __exit close_module(void) {
	cdev_del(&c_dev);
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);

};
	

module_init(start_module);
module_exit(close_module);

MODULE_AUTHOR("Patrik Pfaffenbauer");
MODULE_DESCRIPTION("Inits the systemtera.server boot leds");
MODULE_LICENSE("GPL");
