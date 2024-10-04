/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"


static void advance_pointer(struct aesd_circular_buffer *buffer)
{
    if (buffer->full)
    {
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    buffer->full = (buffer->in_offs == buffer->out_offs);
}
/*---------------------------------------------------------------------------*/

static void retreat_pointer(struct aesd_circular_buffer *buffer)
{
    buffer->full = false;
    buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
}
/*---------------------------------------------------------------------------*/

long aesd_circular_buffer_get_new_offset(const struct aesd_circular_buffer *buffer, uint32_t entry, uint32_t offset)
{
    long new_offset = 0;
    struct aesd_circular_buffer l_buffer;
    unsigned int num_entries = 0;

    if(buffer != NULL)
    {
        memset(&l_buffer, 0, sizeof(struct aesd_circular_buffer));
        memcpy(&l_buffer, buffer, sizeof(struct aesd_circular_buffer));

        num_entries = ((!l_buffer.full) ? (l_buffer.in_offs - l_buffer.out_offs):AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);

        if(num_entries <= entry)
        {
            /* cmd out of range */
            return -EINVAL;
        }

        do
        {
            if(entry == 0)
            {   
                if(l_buffer.entry[l_buffer.out_offs].size >= offset)
                {
                    new_offset += offset;
                }
                else
                {
                    return -EINVAL;
                }
            }
            else
            {
				new_offset += l_buffer.entry[l_buffer.out_offs].size;
                retreat_pointer(&l_buffer);
            }
        }while(entry-- != 0);
    }

    return new_offset;
}

unsigned long aesd_circular_buffer_get_size(const struct aesd_circular_buffer *buffer)
{
    unsigned long buff_size = 0;
    struct aesd_circular_buffer l_buffer;

    if(buffer != NULL)
    {
        if((!buffer->full) && (buffer->in_offs == buffer->out_offs))
        {
            /* buffer is empty */
        }
        else
        {
            memset(&l_buffer, 0, sizeof(struct aesd_circular_buffer));
            memcpy(&l_buffer, buffer, sizeof(struct aesd_circular_buffer));

            do
            {
                buff_size += l_buffer.entry[l_buffer.out_offs].size;
                retreat_pointer(&l_buffer);
            } while (l_buffer.out_offs != l_buffer.in_offs);
            
        }
    }

    return buff_size;
}

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    struct aesd_circular_buffer l_buffer;
    unsigned int index_cnt = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    if(buffer != NULL && entry_offset_byte_rtn != NULL)
    {
        memset(&l_buffer, 0, sizeof(struct aesd_circular_buffer));
        memcpy(&l_buffer, buffer, sizeof(struct aesd_circular_buffer));

        do
        {
            if(l_buffer.entry[l_buffer.out_offs].size == 0)
            {
                return NULL;
            }
            else if(l_buffer.entry[l_buffer.out_offs].size <= char_offset )
            {
                char_offset -= l_buffer.entry[l_buffer.out_offs].size;
                retreat_pointer(&l_buffer);
            }
            else
            {
                *entry_offset_byte_rtn = char_offset;
                return &buffer->entry[l_buffer.out_offs];
            }
        }while (--index_cnt != 0);
        
    }
   
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
char * aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    char * ret_val = NULL;

    if(buffer != NULL && add_entry != NULL)
    {       
        if(buffer->full != false)
        {
            ret_val = (char *)buffer->entry[buffer->out_offs].buffptr;
        }
        
        memcpy(&buffer->entry[buffer->in_offs], add_entry, sizeof(struct aesd_buffer_entry));
        advance_pointer(buffer);
    }
    else
    {
        /* Invalid*/
    }

    return ret_val;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
