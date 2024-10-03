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
    size_t chars_scanned = 0;
    size_t prev_chars_scanned = 0;
    uint32_t entries_scanned = 0;
    uint8_t read_pos = buffer->out_offs;
    uint8_t num_entries =  get_length(buffer);
    bool entry_found = false;
    //First we need to know which entry the char_offset would lie within
    while(!entry_found){
        //Check to make sure we haven't reached the end
        if(entries_scanned == num_entries){
            return NULL;
        }
        //Store the previous amount
        prev_chars_scanned = chars_scanned;
        //We add to the chars searched
        chars_scanned += buffer->entry[read_pos].size;
        // We also increment the entry offset
        entries_scanned++;
        //We advance the read_pos
        read_pos = increment_pointer(read_pos);
        //Check if the chars processed has passed the offset
        if(chars_scanned >= char_offset+1){
            entry_found = true;
        }
    }
    *entry_offset_byte_rtn = char_offset - prev_chars_scanned;
    uint8_t entry_index = (buffer->out_offs + entries_scanned - 1) %AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    //Return the right entry
    return &buffer->entry[entry_index];

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
