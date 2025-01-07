/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/fs.h> // file_operations
#include <linux/string.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Mohsin Sardar"); 
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static long aesd_adjust_file_offset(struct file *filp, uint32_t cmd, uint32_t cmd_offset);


int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev = NULL;

    PDEBUG("open");
    if((inode != NULL) && (filp != NULL))
    {
        dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
        filp->private_data = dev;
    }
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *l_devp = NULL;
    struct aesd_buffer_entry *k_entry = NULL;
    size_t buf_pos = 0;
    size_t read_len = 0;

    ssize_t retval = -EFAULT;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    if((filp != NULL) && (f_pos != NULL) && (buf != NULL))
    {
        l_devp = (struct aesd_dev *)filp->private_data;
        if(l_devp != NULL)
        {
            if(mutex_lock_interruptible(&l_devp->lock))
            {
                return -ERESTARTSYS;
            }

            k_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&l_devp->buffer, (size_t)*f_pos, &buf_pos);  

            mutex_unlock(&l_devp->lock);
            
            if ((k_entry != NULL) && (k_entry->buffptr != NULL))
            {
                PDEBUG("entry size: %zu, buffer pos: %zu", k_entry->size, buf_pos);
                read_len = ((k_entry->size - buf_pos) < count) ? (k_entry->size - buf_pos) : count;                
                read_len -= copy_to_user(buf, &k_entry->buffptr[buf_pos], read_len);
                *f_pos = (filp->f_pos + read_len);
                retval = (ssize_t)read_len;
            } 
            else
            {
                PDEBUG("no entry found");
                retval = 0;
            }
        }  
        else
        {
            PDEBUG("filp->private_data is NULL");
        }      
    }

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_buffer_entry k_entry;
    struct aesd_dev *l_devp = NULL;
    static char * k_buf = NULL;
    static size_t k_buf_size = 0;
    char *old_entry = NULL;
    ssize_t retval = -ENOMEM;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if((filp != NULL) && (f_pos != NULL))
    {
        l_devp = (struct aesd_dev *)filp->private_data;
        if(l_devp == NULL)
        {
            return retval;
        }

        if(mutex_lock_interruptible(&l_devp->lock))
        {
            return -ERESTARTSYS;
        }

        k_buf_size += count;
        k_buf = krealloc(k_buf, (k_buf_size*sizeof(char)), GFP_KERNEL);

        if(k_buf != NULL) 
        {
            PDEBUG("Allocated entry, %lu", (uintptr_t)k_buf);
            if (buf != NULL)
            {
                if(copy_from_user(&k_buf[k_buf_size - count], buf, count) != 0)
                {
                    PDEBUG("copy_from_user failed");
                    goto cleanup;
                }
                else
                {
                    *f_pos = (filp->f_pos + count);
                    if(k_buf[k_buf_size - 1] == '\n')
                    {
                        k_entry.size = k_buf_size;  
                        k_entry.buffptr = k_buf; 
                        PDEBUG("entry size: %zu", k_entry.size);
                        PDEBUG("Adding buffer %lu to circular buffer", (uintptr_t)k_buf);
                        old_entry = aesd_circular_buffer_add_entry(&l_devp->buffer, &k_entry);
                        k_buf = NULL;
                        k_buf_size = 0;
                        mutex_unlock(&l_devp->lock);

                        if(old_entry != NULL)
                        {
                            PDEBUG("Freeing entry, %lu", (uintptr_t)old_entry);
                            kfree(old_entry);
                        }
                        (void)k_buf;
                        (void)k_entry;
                        retval = (ssize_t)k_entry.size;
                    }
                    else
                    {
                        mutex_unlock(&l_devp->lock);
                        retval = (ssize_t)count;
                    }                    
                }
            }

            return retval;
        }
        else
        {
            goto cleanup;
        }
    }
    else
    {
        return retval;
    }

    cleanup:
    {
        if(k_buf != NULL)
        {
            PDEBUG("Cleanup: Freeing entry, %lu", (uintptr_t)k_buf);
            kfree(k_buf);
        }
		
        mutex_unlock(&l_devp->lock);
    }
    
    return retval;
}

loff_t aesd_seek(struct file *filp, loff_t offset, int whence)
{
    loff_t new_pos = 0;
    struct aesd_dev *l_devp = NULL;

    if(filp != NULL)
    {
        l_devp = (struct aesd_dev *)filp->private_data;
        if(l_devp == NULL)
        {
            return 0;
        }

        if(mutex_lock_interruptible(&l_devp->lock))
        {
            return 0;
        }

        new_pos = fixed_size_llseek(filp, offset, whence, aesd_circular_buffer_get_size((const struct aesd_circular_buffer *)&l_devp->buffer));
        PDEBUG("seeking: offset %lld, new f_pos %lld", offset, new_pos);
        filp->f_pos = new_pos;
        mutex_unlock(&l_devp->lock);
    }
    else
    {
        /* null file pointer, return 0 */
    }

    return new_pos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_seekto seekto;
    long retval = EFAULT;

    if(filp != NULL)
    {
        switch(cmd)
        {
            case AESDCHAR_IOCSEEKTO:
			{
				if(copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
				{
					retval = EFAULT;
					PDEBUG("ioctl copy_from_user Error");
				}
				else
				{
					retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
					filp->f_pos = (loff_t)retval;
				}
				break;
			}
			default:
			{
				PDEBUG("ioctl unkown cmd Error");
				retval = EFAULT;
			}
                
        }
    }

    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_seek,
    .unlocked_ioctl = aesd_ioctl
};

static long aesd_adjust_file_offset(struct file *filp, uint32_t cmd, uint32_t cmd_offset)
{
    struct aesd_dev *l_devp = NULL;
    long retval = EFAULT;

    if(filp != NULL)
    {
        l_devp = (struct aesd_dev *)filp->private_data;
        if(l_devp == NULL)
        {
            return retval;
        }

        if(mutex_lock_interruptible(&l_devp->lock))
        {
            return retval;
        }
		
        retval = aesd_circular_buffer_get_new_offset((const struct aesd_circular_buffer *)&l_devp->buffer, cmd, cmd_offset);
        PDEBUG("ioctl new f_pos %ld", retval);

        mutex_unlock(&l_devp->lock);  
	}
    
    return retval;
}

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        //printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
	uint8_t i;
	
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    for (i = 0; i < (sizeof(aesd_device.buffer.entry)/sizeof(struct aesd_buffer_entry)); i++)
    {
		if (aesd_device.buffer.entry[i].buffptr != NULL)
		{
			PDEBUG("Freeing entry, %lu", (uintptr_t)aesd_device.buffer.entry[i].buffptr);
			kfree(aesd_device.buffer.entry[i].buffptr);
		}
		else
		{
			/* no entry */
		}
	}

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
