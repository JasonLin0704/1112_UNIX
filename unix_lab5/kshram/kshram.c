#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm.h>

#include "kshram.h"

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
char *mem[8];
int sz[8];

static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	int m = iminor(fp->f_inode);

	// printk(KERN_INFO "kshram: ioctl cmd=%u arg=%lu.\n", cmd, arg);

	if(cmd == KSHRAM_GETSLOTS){
		// printk(KERN_INFO "KSHRAM_GETSLOTS\n");
		ret = 8;
	}
	else if(cmd == KSHRAM_GETSIZE){
		// printk(KERN_INFO "KSHRAM_GETSIZE\n");
		ret = sz[m];
	}
	else if(cmd == KSHRAM_SETSIZE){
		// printk(KERN_INFO "KSHRAM_SETSIZE\n");
		mem[m] = krealloc(mem[m], arg, GFP_KERNEL);
		sz[m] = arg;
		ret = sz[m];
	}
	return ret;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vma) {
    int m = iminor(fp->f_inode);
	unsigned long size = vma->vm_end - vma->vm_start;
	struct page *page = virt_to_page((unsigned long)(mem[m]) + (vma->vm_pgoff << PAGE_SHIFT)); 

	printk(KERN_INFO "kshram/mmap: idx %d size %d\n", m, sz[m]);

	if(size > sz[m]){
		printk(KERN_INFO "EINVAL\n");
    }
	
	if(remap_pfn_range(vma, vma->vm_start, page_to_pfn(page), size, vma->vm_page_prot) != 0){
        printk(KERN_INFO "EFAULT\n");
    }
	
    return 0;
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kshram_dev_ioctl,
	.mmap = kshram_dev_mmap
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	// char buf[] = "`hello, world!` in /proc.\n";
	for(int i = 0; i < 8; i++){
		seq_printf(m, "0%d: %d\n", i, sz[i]);
	}
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{	
	char device_name[16];

	// Allocate memory
	for(int i = 0; i < 8; i++){
		mem[i] = kzalloc(4096, GFP_KERNEL);
		sz[i] = 4096;
		printk("kshram%d: 4096 bytes allocated @ %lx\n", i, (unsigned long) mem[i]);
	}
	
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 8, "updev") < 0) 
		return -1;
	if((clazz = class_create(THIS_MODULE, "kshram")) == NULL) 
		goto release_region;
    clazz->devnode = kshram_devnode;
	
	for(int i = 0; i < 8; i++){
		sprintf(device_name, "kshram%d", i);
		if(device_create(clazz, NULL, MKDEV(MAJOR(devnum), i), NULL, device_name) == NULL) 
			goto release_class;
	}

	cdev_init(&c_dev, &kshram_dev_fops);
	if(cdev_add(&c_dev, devnum, 8) == -1) 
		goto release_device;
	
	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	for(int i = 0; i < 8; i++){
		device_destroy(clazz, MKDEV(MAJOR(devnum), i));
	}
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 8);
	for(int i = 0; i < 8; i++) kfree(mem[i]);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	remove_proc_entry("kshram", NULL);
	cdev_del(&c_dev);
	for(int i = 0; i < 8; i++) device_destroy(clazz, MKDEV(MAJOR(devnum), i));	
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 8);
	for(int i = 0; i < 8; i++) kfree(mem[i]);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jason");
MODULE_DESCRIPTION("Lab5");
