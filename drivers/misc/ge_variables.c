/*
 * Variables export driver
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
#include <linux/ge_variables.h>


struct variable_attribute {
	struct kobj_attribute attr;
	unsigned int (*get_value)(void);
	unsigned int value;
};

struct variable_data {
	struct kobject *subdir;
	struct variable_attribute init;
	struct variable_attribute value;
};

struct driver_data {
	struct kobject *dir;
	unsigned int num_variables;
	struct variable_data vdata[];
};

static ssize_t init_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct variable_attribute *data = container_of(attr,
			struct variable_attribute, attr);
	return snprintf(buf, PAGE_SIZE, "%u\n", data->value);
}

static ssize_t show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct variable_attribute *data = container_of(attr,
			struct variable_attribute, attr);
	unsigned int value = data->get_value ? data->get_value() : data->value;
	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

static int ge_variables_probe(struct platform_device *pdev)
{
	struct ge_variables_platform_data *pdata = pdev->dev.platform_data;
	struct driver_data *data;
	struct variable_data *dest;
	int i, ret;

	if (!pdata)
		return -EBUSY;

	data = kzalloc(sizeof(struct driver_data) + sizeof(struct variable_data)
			* pdata->num_variables, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dir = kobject_create_and_add("values", &pdev->dev.kobj);
	if (!data->dir) {
		dev_err(&pdev->dev, "Cannot create sysfs variables dir 'values'\n");
		kfree(data);
		return -EIO;
	}

	data->num_variables = pdata->num_variables;
	for (i = 0; i < pdata->num_variables; i++) {
		struct ge_variable *src = &pdata->variables[i];
		dest = &data->vdata[i];

		if (!src->name) {
			dev_err(&pdev->dev, "Variable name must be set\n");
			ret = -EINVAL;
			goto err;
		}

		dest->subdir = kobject_create_and_add(src->name, data->dir);
		if (!dest->subdir) {
			dev_err(&pdev->dev, "Cannot create sysfs variable dir '%s'\n",
					src->name);
			ret = -EIO;
			goto err;
		}

		dest->init.value = src->get_value ? src->get_value() : src->value;
		dest->init.attr.show = init_show;
		sysfs_attr_init(&dest->init.attr.attr);
		dest->init.attr.attr.name = "initial_value";
		dest->init.attr.attr.mode = S_IRUGO;

		dest->value.value = dest->init.value;
		dest->value.get_value = src->get_value;
		dest->value.attr.show = show;
		sysfs_attr_init(&dest->value.attr.attr);
		dest->value.attr.attr.name = "value";
		dest->value.attr.attr.mode = S_IRUGO;

		ret = sysfs_create_file(dest->subdir, &dest->init.attr.attr);
		if (ret)
			goto err_dir;

		ret = sysfs_create_file(dest->subdir, &dest->value.attr.attr);
		if (ret)
			goto err_file;
	}

	platform_set_drvdata(pdev, data);
	return 0;

err_file:
	sysfs_remove_file(dest->subdir, &dest->init.attr.attr);
err_dir:
	kobject_put(dest->subdir);
err:
	for (--i; i >= 0; i--) {
		dest = &data->vdata[i];
		sysfs_remove_file(dest->subdir, &dest->init.attr.attr);
		sysfs_remove_file(dest->subdir, &dest->value.attr.attr);
		kobject_put(dest->subdir);
	}
	kobject_put(data->dir);
	kfree(data);
	return ret;
}

static int __exit ge_variables_remove(struct platform_device *pdev)
{
	struct driver_data *data = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < data->num_variables; i++) {
		struct variable_data *dest = &data->vdata[i];
		sysfs_remove_file(dest->subdir, &dest->init.attr.attr);
		sysfs_remove_file(dest->subdir, &dest->value.attr.attr);
		kobject_put(dest->subdir);
	}

	kobject_put(data->dir);
	kfree(data);
	return 0;
}

static struct platform_driver ge_variables_driver = {
	.driver = {
		.name  = "ge_variables",
		.owner = THIS_MODULE,
	},
	.probe         = ge_variables_probe,
	.remove        = __exit_p(ge_variables_remove),
};

static int __init ge_variables_init(void)
{
	return platform_driver_register(&ge_variables_driver);
}

static void __exit ge_variables_exit(void)
{
	platform_driver_unregister(&ge_variables_driver);
}

module_init(ge_variables_init);
module_exit(ge_variables_exit);

MODULE_DESCRIPTION("Ginzinger Variables Export Driver");
MODULE_AUTHOR("Melchior Franz <melchior.franz@ginzinger.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:variables");
