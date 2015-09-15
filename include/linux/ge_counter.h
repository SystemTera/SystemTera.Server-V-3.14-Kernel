/*
 * Definitions for counter driver
 *
 * Copyright (C) 2012 Melchior FRANZ <melchior.franz@ginzinger.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 */

#ifndef _GE_COUNTER_H
#define _GE_COUNTER_H

struct ge_counter {
	const char *name;
	unsigned int gpio;                /* GPIO number */
	unsigned int irq_type;            /* IRQ_TYPE_EDGE_RISING etc. (see include/linux/irq.h) */
	unsigned long interval;           /* count interval in ms (jiffy resolution);
	                                     0: don't use interval counting at all */
	bool reset_on_read;
};

struct ge_counter_platform_data {
	struct ge_counter *counter;
	unsigned int num_counter;
};

#endif /* _GE_COUNTER_H */
