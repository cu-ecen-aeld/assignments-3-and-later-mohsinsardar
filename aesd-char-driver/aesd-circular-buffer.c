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
#include <stdlib.h>

#endif

#include "aesd-circular-buffer.h"



uint8_t increment_pointer(uint8_t pos){
    pos = (++pos == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) ? 0 : pos;
    return pos;
}

uint8_t get_length(struct aesd_circular_buffer * buffer){
    uint8_t wrptr = buffer->in_offs;
    uint8_t rdptr = buffer->out_offs;

    if(buffer->full){
        return AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else if(wrptr == rdptr){
        return 0;
    }
    else if(wrptr > rdptr){
        return wrptr-rdptr;
    }
    else{
        return (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - rdptr + wrptr );
    }
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{

   //First allocate memory for the entry buffer content

    //Insert the new entry into the buffer!
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;

    //We check if it was full
    if(buffer->full){
        //Then we advanced the out_offs position circularly
        buffer->out_offs = increment_pointer(buffer->out_offs);
    }

    //Then advance the position of the in_offs ptr circularly
    buffer->in_offs = increment_pointer(buffer->in_offs);

    if(buffer->in_offs == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED){
        buffer->in_offs = 0;
    }

    //After incrementing, check if full
    if(buffer->in_offs == buffer->out_offs){
        buffer->full = true;
    }

}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}


