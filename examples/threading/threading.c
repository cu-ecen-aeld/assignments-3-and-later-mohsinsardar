#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    int res;
    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    usleep((thread_func_args->wait_to_obtain_ms) * 1000);
    res = pthread_mutex_lock(thread_func_args->mutex_);
    if(res != 0)
    {
        ERROR_LOG("Fail to lock thread: %s \n", strerror(res));
        return false;
    }
    usleep((thread_func_args->wait_to_release_ms) * 1000);
    res = pthread_mutex_unlock(thread_func_args->mutex_);
    if(res != 0)
    {
        ERROR_LOG("Fail to unlock thread: %s \n", strerror(res));
        return false;
    }
    thread_func_args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

     struct thread_data *td1 = (struct thread_data*)  malloc(sizeof (struct thread_data));
     if(td1 == NULL)
     {
         ERROR_LOG("Failed to allocate memory\n");
	 return false;
     }

     td1->wait_to_obtain_ms = wait_to_obtain_ms;
     td1->wait_to_release_ms = wait_to_release_ms;
     td1->mutex_ = mutex;
     td1->thread_complete_success = false;

     int res = pthread_create (thread, NULL, threadfunc, (void *) td1);
     
     if(res != 0)
     {
         ERROR_LOG("Fail to create thread: %s \n", strerror(res));
	 free(td1);
	 return false;
     }


    return true;
}

