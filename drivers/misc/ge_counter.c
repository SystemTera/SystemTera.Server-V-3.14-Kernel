/*
 * Counter driver
 *
 * Copyright (C) 2012 Melchior Franz <melchior.franz@ginzinger.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation, version 2.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/jiffies.h>
#include <linux/ge_counter.h>
#include <linux/of_platform.h>
#include <linux/of_gpio.h>


struct counter_data {
	unsigned int gpio;
	unsigned long counter;
	unsigned long start_jiffies;  // jiffies of last counter reset
	unsigned long start_count;    // counts at interval start
	unsigned long interval_count; // counts in last full interval
	unsigned long interval;       // interval time in jiffies
	unsigned long jiffies;        // jiffies at interval start
	bool use_timer;               // use interval counting
	bool interval_count_valid;
	bool reset_on_read;
	spinlock_t lock;
	struct timer_list timer;
	struct kobject *subdir;
	struct kobj_attribute counter_attr;
	struct kobj_attribute elapsed_attr;
	struct kobj_attribute state_attr;
	struct kobj_attribute interval_attr;
	struct kobj_attribute interval_count_attr;
	struct kobj_attribute reset_on_read_attr;
};

struct driver_data {
	struct kobject *dir;
	unsigned int num_counter;
	struct counter_data vdata[];
};

static void reset_interval_counting(struct counter_data *d)
{
	d->start_count = d->counter;
	d->jiffies = jiffies;
	d->interval_count_valid = false;

	if (d->interval)
		mod_timer(&d->timer, d->jiffies + d->interval);
	else if(d->use_timer)
		del_timer_sync(&d->timer);
}

static ssize_t counter_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, counter_attr);
	ssize_t len;
	unsigned long flags;
	spin_lock_irqsave(&d->lock, flags);
	len = snprintf(buf, PAGE_SIZE, "%lu\n", d->counter);
	if (d->reset_on_read) {
		d->counter = 0UL;
		d->start_jiffies = jiffies;
		reset_interval_counting(d);
	}
	spin_unlock_irqrestore(&d->lock, flags);
	return len;
}

static ssize_t counter_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct counter_data *d = container_of(attr, struct counter_data, counter_attr);
	unsigned long old_counter = d->counter;
	unsigned long flags;
	spin_lock_irqsave(&d->lock, flags);
	sscanf(buf, "%lu", &d->counter);

	if (d->counter != old_counter)
		reset_interval_counting(d);

	spin_unlock_irqrestore(&d->lock, flags);
	return count;
}

static ssize_t elapsed_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, elapsed_attr);
	return snprintf(buf, PAGE_SIZE, "%u\n", jiffies_to_msecs(jiffies - d->start_jiffies));
}

static ssize_t elapsed_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct counter_data *d = container_of(attr, struct counter_data, elapsed_attr);
	unsigned int msecs = 0;
	sscanf(buf, "%u", &msecs);
	d->start_jiffies = jiffies - msecs_to_jiffies(msecs);
	return count;
}

static ssize_t reset_on_read_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, reset_on_read_attr);
	ssize_t len;
	unsigned long flags;
	spin_lock_irqsave(&d->lock, flags);
	len = snprintf(buf, PAGE_SIZE, "%u\n", d->reset_on_read ? 1 : 0);
	spin_unlock_irqrestore(&d->lock, flags);
	return len;
}

static ssize_t reset_on_read_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct counter_data *d = container_of(attr, struct counter_data, reset_on_read_attr);
	int tmp;
	unsigned long flags;
	spin_lock_irqsave(&d->lock, flags);
	sscanf(buf, "%i", &tmp);
	d->reset_on_read = tmp ? true : false;
	spin_unlock_irqrestore(&d->lock, flags);
	return count;
}

static ssize_t interval_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, interval_attr);
	return snprintf(buf, PAGE_SIZE, "%u\n", jiffies_to_msecs(d->interval));
}

static ssize_t interval_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct counter_data *d = container_of(attr, struct counter_data, interval_attr);
	unsigned long old_interval = d->interval;
	unsigned long ms;

	sscanf(buf, "%lu", &ms);
	d->interval = msecs_to_jiffies(ms);
	if (d->interval != old_interval) {
		unsigned long flags;
		spin_lock_irqsave(&d->lock, flags);
		reset_interval_counting(d);
		spin_unlock_irqrestore(&d->lock, flags);
	}
	return count;
}

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, state_attr);
	return snprintf(buf, PAGE_SIZE, "%u\n", !gpio_get_value(d->gpio));
}

static ssize_t interval_count_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct counter_data *d = container_of(attr, struct counter_data, interval_count_attr);
	if (d->interval_count_valid)
		return snprintf(buf, PAGE_SIZE, "%lu\n", d->interval_count);
	else
		return snprintf(buf, PAGE_SIZE, "-1\n");
}

static irqreturn_t counter_event(int irq, void *data)
{
	struct counter_data *d = (struct counter_data *)data;
	spin_lock(&d->lock);
	d->counter++;
	spin_unlock(&d->lock);
	return IRQ_HANDLED;
}

static void timeout(unsigned long data)
{
	struct counter_data *d = (struct counter_data *)data;
	spin_lock(&d->lock);
	d->interval_count = d->counter - d->start_count;
	d->start_count = d->counter;
	spin_unlock(&d->lock);

	d->interval_count_valid = true;
	d->jiffies = d->timer.expires = d->jiffies + d->interval;
	add_timer(&d->timer);
}

static void delete_counter(struct counter_data *data)
{
	free_irq(gpio_to_irq(data->gpio), data);
	gpio_free(data->gpio);
	sysfs_remove_file(data->subdir, &data->counter_attr.attr);
	sysfs_remove_file(data->subdir, &data->elapsed_attr.attr);
	sysfs_remove_file(data->subdir, &data->state_attr.attr);
	sysfs_remove_file(data->subdir, &data->reset_on_read_attr.attr);
	if (data->use_timer) {
		del_timer_sync(&data->timer);
		sysfs_remove_file(data->subdir, &data->interval_attr.attr);
		sysfs_remove_file(data->subdir, &data->interval_count_attr.attr);
	}
	kobject_put(data->subdir);
}

#ifdef CONFIG_OF
static struct ge_counter_platform_data *ge_counter_get_devtree_pdata(struct device *dev)
{
	int error, num_counter;
	struct ge_counter_platform_data *pdata;
	struct ge_counter *counter;
	struct device_node *node = dev->of_node, *pp;

	if (!node) {
		error = -ENODEV;
		goto err_out;
	}

	num_counter = of_get_child_count(node);
	if (!num_counter) {
		error = -ENODEV;
		goto err_out;
	}

	pdata = kzalloc(sizeof(*pdata) + num_counter * sizeof(*counter), GFP_KERNEL);
	if (!pdata) {
		error = -ENOMEM;
		goto err_out;
	}

	pdata->counter = (struct ge_counter *)(pdata + 1);
	pdata->num_counter = num_counter;

	counter = pdata->counter;
	for_each_child_of_node(node, pp) {
		const char *name;
		int gpio;
		u32 irq_type;
		u32 interval;

		if (!of_find_property(pp, "gpios", NULL)) {
			pdata->num_counter--;
			dev_warn(dev, "Found counter without gpios\n");
			continue;
		}

		gpio = of_get_gpio_flags(pp, 0, NULL);
		if (gpio < 0) {
			error = gpio;
			if (error != -EPROBE_DEFER)
				dev_err(dev, "Failed to get gpio, error: %d\n", error);
			goto err_free_pdata;
		}

		if (of_property_read_u32(pp, "irq-type", &irq_type))
			irq_type = IRQ_TYPE_EDGE_RISING;

		if (of_property_read_u32(pp, "interval", &interval))
			interval = 0;

		name = of_get_property(pp, "label", NULL);
		if (!name)
			name = pp->name;

		counter->name = name;
		counter->gpio = gpio;
		counter->irq_type = irq_type;
		counter->interval = interval;
		counter->reset_on_read = of_property_read_bool(pp, "reset-on-read");
		counter++;
	}

	return pdata;

err_free_pdata:
	kfree(pdata);
err_out:
	return ERR_PTR(error);
}

static struct of_device_id ge_counter_of_match[] = {
	{ .compatible = "ginzinger,ge_counter", },
	{ },
};
MODULE_DEVICE_TABLE(of, ge_counter_of_match);

#else
static inline struct ge_counter_platform_data *ge_counter_get_devtree_pdata(struct device *dev)
{
	dev_err(dev, "no platform data defined\n");
	return ERR_PTR(-ENODEV);
}
#endif // CONFIG_OF

static int ge_counter_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ge_counter_platform_data *pdata = dev_get_platdata(dev);
	struct driver_data *data;
	struct counter_data *dest;
	unsigned int irq;
	int i, ret;

	if (!pdata) {
		pdata = ge_counter_get_devtree_pdata(dev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}

	data = kzalloc(sizeof(struct driver_data) + sizeof(struct counter_data)
			* pdata->num_counter, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dir = kobject_create_and_add("counter", &pdev->dev.kobj);
	if (!data->dir) {
		dev_err(&pdev->dev, "Cannot create sysfs counter dir 'counter'\n");
		kfree(data);
		return -EIO;
	}

	data->num_counter = pdata->num_counter;
	for (i = 0; i < pdata->num_counter; i++) {
		struct ge_counter *src = &pdata->counter[i];
		dest = &data->vdata[i];

		if (!src->name) {
			dev_err(&pdev->dev, "Counter name must be set\n");
			ret = -EINVAL;
			goto err;
		}

		if (!src->gpio || gpio_request(src->gpio, src->name)) {
			dev_err(&pdev->dev, "Invalid counter GPIO %d\n", src->gpio);
			ret = -EINVAL;
			goto err;
		}

		gpio_direction_input(src->gpio);
		irq = gpio_to_irq(src->gpio);
		enable_irq_wake(irq);
		ret = request_any_context_irq(irq, counter_event, src->irq_type,
				"ge_counter", dest);
		if (ret < 0) {
			dev_err(&pdev->dev, "Cannot request IRQ %u for GPIO %u", irq, src->gpio);
			ret = -EINVAL;
			goto err_gpio;
		}

		dest->subdir = kobject_create_and_add(src->name, data->dir);
		if (!dest->subdir) {
			dev_err(&pdev->dev, "Cannot create sysfs counter dir '%s'\n",
					src->name);
			ret = -EIO;
			goto err_irq;
		}

		spin_lock_init(&dest->lock);

		dest->gpio = src->gpio;
		dest->interval = msecs_to_jiffies(src->interval);
		dest->counter = 0UL;
		dest->start_jiffies = jiffies;
		dest->start_count = 0UL;
		dest->reset_on_read = src->reset_on_read;
		dest->use_timer = false;
		dest->interval_count_valid = false;

		dest->counter_attr.show = counter_show;
		dest->counter_attr.store = counter_store;
		sysfs_attr_init(&dest->counter_attr.attr);
		dest->counter_attr.attr.name = "counter";
		dest->counter_attr.attr.mode = S_IRUGO | S_IWUSR;

		ret = sysfs_create_file(dest->subdir, &dest->counter_attr.attr);
		if (ret)
			goto err_dir;

		dest->elapsed_attr.show = elapsed_show;
		dest->elapsed_attr.store = elapsed_store;
		sysfs_attr_init(&dest->elapsed_attr.attr);
		dest->elapsed_attr.attr.name = "elapsed";
		dest->elapsed_attr.attr.mode = S_IRUGO | S_IWUSR;

		ret = sysfs_create_file(dest->subdir, &dest->elapsed_attr.attr);
		if (ret)
			goto err_file1;

		dest->state_attr.show = state_show;
		sysfs_attr_init(&dest->state_attr.attr);
		dest->state_attr.attr.name = "state";
		dest->state_attr.attr.mode = S_IRUGO;

		ret = sysfs_create_file(dest->subdir, &dest->state_attr.attr);
		if (ret)
			goto err_file2;

		dest->reset_on_read_attr.show = reset_on_read_show;
		dest->reset_on_read_attr.store = reset_on_read_store;
		sysfs_attr_init(&dest->reset_on_read_attr.attr);
		dest->reset_on_read_attr.attr.name = "reset_on_read";
		dest->reset_on_read_attr.attr.mode = S_IRUGO | S_IWUSR;

		ret = sysfs_create_file(dest->subdir, &dest->reset_on_read_attr.attr);
		if (ret)
			goto err_file3;

		if (src->interval) {
			dest->interval_attr.show = interval_show;
			dest->interval_attr.store = interval_store;
			sysfs_attr_init(&dest->interval_attr.attr);
			dest->interval_attr.attr.name = "interval";
			dest->interval_attr.attr.mode = S_IRUGO | S_IWUSR;

			ret = sysfs_create_file(dest->subdir, &dest->interval_attr.attr);
			if (ret)
				goto err_file4;

			dest->interval_count_attr.show = interval_count_show;
			sysfs_attr_init(&dest->interval_count_attr.attr);
			dest->interval_count_attr.attr.name = "interval_count";
			dest->interval_count_attr.attr.mode = S_IRUGO;

			ret = sysfs_create_file(dest->subdir, &dest->interval_count_attr.attr);
			if (ret)
				goto err_file5;

			dest->use_timer = true;
			init_timer(&dest->timer);
			dest->timer.data = (unsigned long)dest;
			dest->timer.function = timeout;
			dest->jiffies = jiffies;
			dest->timer.expires = jiffies + dest->interval;
			add_timer(&dest->timer);
		}
	}

	platform_set_drvdata(pdev, data);
	return 0;

err_file5:
	sysfs_remove_file(dest->subdir, &dest->interval_attr.attr);
err_file4:
	sysfs_remove_file(dest->subdir, &dest->reset_on_read_attr.attr);
err_file3:
	sysfs_remove_file(dest->subdir, &dest->state_attr.attr);
err_file2:
	sysfs_remove_file(dest->subdir, &dest->elapsed_attr.attr);
err_file1:
	sysfs_remove_file(dest->subdir, &dest->counter_attr.attr);
err_dir:
	kobject_put(dest->subdir);
err_irq:
	free_irq(irq, dest);
err_gpio:
	gpio_free(dest->gpio);
err:
	for (--i; i >= 0; i--)
		delete_counter(&data->vdata[i]);

	kobject_put(data->dir);
	kfree(data);
	return ret;
}

static int __exit ge_counter_remove(struct platform_device *pdev)
{
	struct driver_data *data = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < data->num_counter; i++)
		delete_counter(&data->vdata[i]);

	kobject_put(data->dir);
	kfree(data);
	return 0;
}

static struct platform_driver ge_counter_driver = {
	.driver = {
		.name = "ge_counter",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(ge_counter_of_match),
	},
	.probe = ge_counter_probe,
	.remove = __exit_p(ge_counter_remove),
};

static int __init ge_counter_init(void)
{
	return platform_driver_register(&ge_counter_driver);
}

static void __exit ge_counter_exit(void)
{
	platform_driver_unregister(&ge_counter_driver);
}

module_init(ge_counter_init);
module_exit(ge_counter_exit);

MODULE_DESCRIPTION("Ginzinger Counter Driver");
MODULE_AUTHOR("Melchior Franz <melchior.franz@ginzinger.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:counter");
