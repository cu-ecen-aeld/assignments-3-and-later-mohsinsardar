#include "systemcalls.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
//#include <sys/types.h>
#include <sys/wait.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    if(system(cmd) == -1)
       return false;
    else
       return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int status;
    bool ret = false;
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    va_end(args);

    const pid_t pid = fork();
    if(pid == 0)
    {
        if(execv(command[0],command) == -1)
	{
          	//printf("\n Error MMS \n");
    		exit(EXIT_FAILURE);
	}
	else
	   exit(EXIT_SUCCESS);
    }
    else if(pid > 0)
    {
       if(waitpid(pid, &status, 0) == -1)
       {
          //printf("\n Error MMS1: %d \n",status);
          ret = false;
       }
       
	if( WIFEXITED(status))        /* examine exit status */
	{
	   if(WEXITSTATUS(status) == EXIT_SUCCESS)
	       ret=true;
	   else
	       ret=false;
	}
    }
    else
    {
       //fork failed
       ret = false;
    }


    return ret;
}


/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i, status;
    bool ret = false;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    va_end(args);

    int fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd < 0) { perror("open"); return false; }
    const pid_t pid = fork();
    if(pid == 0)
    {
        if (dup2(fd, 1) < 0) { perror("dup2"); exit(EXIT_FAILURE); }
        close(fd);
        if(execv(command[0],command) == -1)
	{
          	//printf("\n Error MMS \n");
    		exit(EXIT_FAILURE);
	}
	else
	   exit(EXIT_SUCCESS);
    }
    else if(pid > 0)
    {
       close(fd);
       if(waitpid(pid, &status, 0) == -1)
       {
          //printf("\n Error MMS1: %d \n",status);
          ret = false;
       }
       
	if( WIFEXITED(status))        /* examine exit status */
	{
	   if(WEXITSTATUS(status) == EXIT_SUCCESS)
	       ret=true;
	   else
	       ret=false;
	}
    }
    else
    {
       //fork failed
       ret = false;
    }


    return ret;
}
