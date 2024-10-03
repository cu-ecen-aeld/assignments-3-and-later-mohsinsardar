/****************************************************************************
 *  Author:     Daniel Mendez
 *  Course:     ECEN 5823
 *  Project:    Assignment_9
 *
 ****************************************************************************/

/**
 * @file        aesdsocket.c
 * @brief       Source file for socker server
 *
 * @details     This file contains the function to initialize the LETIMER0 module
 *              with the following settings:
 *
 * @sources     - Beej Guide to Network Programming :https://beej.us/guide/bgnet/html/ Leveraged code from 6.1 A simple Stream Server with modifications
 *              - Linux System Programming : Chapter 10 Signals Page 342
 *

 *
 * @date        1 Nov 2023
 * @version     2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <regex.h>
#include "queue.h"
#include "aesd_ioctl.h"


#define USE_AESD_CHAR_DEVICE 1

#define PORT "9000"
#define BUFFER_SIZE 1024
#define BACKLOG 10   // how many pending connections queue will hold

#if USE_AESD_CHAR_DEVICE
#define OUTPUT_FILE "/dev/aesdchar"
#else
#define OUTPUT_FILE "/var/tmp/aesdsocketdata"
#endif

#define ERROR_RESULT (-1)

pthread_mutex_t logFileMutex;
int server_socket_fd;

typedef struct thread_data {

    int thread_num;
    int client_socket;
    pthread_mutex_t *log_file_mutex;
    bool thread_complete_success;
} thread_data_t;


typedef struct thread_node {
    pthread_t thread_id;
    thread_data_t *thread_params;
    SLIST_ENTRY(thread_node) entries;
} thread_node_t;

SLIST_HEAD(threadList, thread_node) threadListHead = SLIST_HEAD_INITIALIZER(threadListHead);

static void signal_handler(int signo) {
    //Free the linked list
    syslog(LOG_DEBUG, "Caught signal in sign handler %d", signo);
    thread_node_t *currentElement, *tempElement;
    SLIST_FOREACH_SAFE(currentElement, &threadListHead, entries, tempElement) {
        //Remove the output file
        char temp_file[256];
        snprintf(temp_file, sizeof(temp_file), "/var/tmp/tempfile_%d.txt", currentElement->thread_params->thread_num);
        if (remove(temp_file) == 0) {
            printf("File '%s' deleted successfully.\n", temp_file);
        }
        syslog(LOG_DEBUG, "cleaned up files in handler");
        //Join all running threads
        //IDK if this should be pthread_cancel or pthread_join
        pthread_join(currentElement->thread_id, NULL);
        // Remove the element safely from the list.
        SLIST_REMOVE(&threadListHead, currentElement, thread_node, entries);
        //Free the thread param data
        free(currentElement->thread_params);
        //Free the node itself
        free(currentElement);
    }
    //destroy the mutex
    pthread_mutex_destroy(&logFileMutex);
    //close the server socket
    close(server_socket_fd);
    printf("Signal Recieved %d \r\n", signo);
    syslog(LOG_DEBUG, "closed socket and exiting now");
    exit(EXIT_SUCCESS);
}

static void alarm_handler(int signo) {
    printf("Alarm Recieved %d \r\n", signo);
    char timestamp[64];
    time_t currentTime;
    struct tm *timeInfo;

    //Get the current time
    time(&currentTime);
    timeInfo = localtime(&currentTime);
    //Store the string formatted as RFC
    strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %T %z\n", timeInfo);
    //lock the mutex
    pthread_mutex_lock(&logFileMutex);

    //Then we open the main log file creating it if it doesn't exist
    int log_fd = open(OUTPUT_FILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
    //Write to the file
    if (write(log_fd, timestamp, strlen(timestamp)) == -1) {
        perror("Error writing to destination file");
        close(log_fd);
    }
    //close the file
    close(log_fd);
    //Unlock the mutex
    pthread_mutex_unlock(&logFileMutex);

    //Schedule the next alarm
    alarm(10);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

bool check_for_ioctl_cmd(char *temp_file, uint32_t *cmd_num, uint32_t *cmd_offset) {
    char pattern[] = "(AESDCHAR_IOCSEEKTO:)([0-9]+),([0-9]+)";
    char cmd_num_str[100];
    char cmd_offset_str[100];
    regex_t regex;
    regmatch_t matches[4];
    bool result;

    // Compile the regular expression
    int reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Regex compilation failed\n");
        exit(EXIT_FAILURE);
    }

    //Since the fd is open we simply read the file into memory;
    char temp_buffer[BUFFER_SIZE];
    int temp_fd = open(temp_file, O_CREAT | O_RDWR, 0666);
    //Read in the entire file as much as the buffer can hold
    size_t num_bytes = read(temp_fd, temp_buffer, BUFFER_SIZE);
    //Insert a null char
    temp_buffer[num_bytes] = '\0';
    //Execute the regex
    int match_result = regexec(&regex, temp_buffer, 4, matches, 0);

    if (match_result != 0) {
        result = false;
    } else {
        //We have a match in the template so extract the numbers
        int start1 = matches[2].rm_so;
        int end1 = matches[2].rm_eo;
        strncpy(cmd_num_str, temp_buffer + start1, end1 - start1);
        cmd_num_str[end1 - start1] = '\0';

        int start2 = matches[3].rm_so;
        int end2 = matches[3].rm_eo;
        strncpy(cmd_offset_str, temp_buffer + start2, end2 - start2);
        cmd_offset_str[end2 - start2] = '\0';

        // Convert the captured number strings to uint32_t
        *cmd_num = (uint32_t) strtoul(cmd_num_str, NULL, 10);
        *cmd_offset = (uint32_t) strtoul(cmd_offset_str, NULL, 10);

        result = true;
    }

    //Close the fd
    close(temp_fd);
    return result;
}


void daemonize() {
    // Fork off the parent process
    pid_t pid = fork();

    // Exit if the fork was unsuccessful
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    // If we got a good PID, then we can exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    pid_t sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    // Change the current working directory (optional)
    // chdir("/");

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null or log files
    int fd = open("/dev/null", O_RDWR);
    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) {
            close(fd);
        }
    }


}

void *thread_function(void *thread_param) {

    //Get the params
    thread_data_t *threadData = (thread_data_t *) thread_param;
    int client_socket = threadData->client_socket;
    ssize_t bytes_received;
    char recv_buffer[BUFFER_SIZE];
    ssize_t bytesRead;
    //Setup the temp file name
    char temp_file[256];
    //Temp buffer for copying over data
    char temp_file_buffer[BUFFER_SIZE];
    snprintf(temp_file, sizeof(temp_file), "/var/tmp/tempfile_%d.txt", threadData->thread_num);
    printf("Thread %d waiting on data!  \r\n", threadData->thread_num);
    int log_fd;
    //Waits for data
    while (1) {
        bytes_received = recv(client_socket, recv_buffer, BUFFER_SIZE, 0);
        if (bytes_received == -1) {
            perror("recv");
            close(client_socket);
            break;
        } else if (bytes_received == 0) {
            // Connection closed by the client
            syslog(LOG_INFO, "Closed connection from thread %d \r\n", threadData->thread_num);
            printf("Connection closed \r\n");
            close(client_socket);
            break;
        }
        //Iterate through the bytes received and add them to the recv_buffer to write to the file
        for (int i = 0; i < bytes_received; i++) {

            char new_char = recv_buffer[i];
            //If new_char is not a newline then just add it in to the temp file
            if (new_char != '\n') {
                int temp_fd = open(temp_file, O_CREAT | O_WRONLY | O_APPEND, 0666);
                //Check temp file return code
                if (temp_fd == -1) {
                    perror("Error opening temporary file for writing");
                    exit(EXIT_FAILURE);
                }
                write(temp_fd, &new_char, sizeof(char));
                //Then close the fd
                close(temp_fd);
            } else {

                struct aesd_seekto seek_params;
                //We check the current temp file to see if the string matches our command
                bool ioctl_called = check_for_ioctl_cmd(temp_file, &(seek_params.write_cmd),
                                                        &(seek_params.write_cmd_offset));
                if (ioctl_called) {

                    int temp_fd = open(temp_file, O_CREAT | O_RDWR, 0666);
                    //We just empty the log file and continue since we don't write
                    if (ftruncate(temp_fd, 0) == -1) {
                        perror("Error truncating file");
                        close(temp_fd); // Close the file descriptor
                    }
                    //Now we perform the ioctl cmd
                    printf("Performing ioctl_cmd with cmd_offsed %d and write_cmd_offset of %d \r\n",
                           seek_params.write_cmd, seek_params.write_cmd_offset);
                    //Do the ioctly seek

                    // Open the device or driver (replace with the appropriate file path)
                    log_fd = open(OUTPUT_FILE, O_RDWR);
                    if (log_fd == -1) {
                        perror("Failed to open device");
                        continue;
                    }

                    if (ioctl(log_fd, AESDCHAR_IOCSEEKTO, &seek_params) == -1) {
                        perror("IOCTL operation failed");
                    }
                    //Close temp file descriptor
                    //close(ioctl_fd);
                    close(temp_fd);


                }
                    //Only append to log file if ioctl command not called
                else {
                    //Open it in Read and Writing mode
                    int temp_fd = open(temp_file, O_CREAT | O_RDWR, 0666);
                    //Check temp file return code
                    if (temp_fd == -1) {
                        perror("Error opening temporary file for copying");
                        exit(EXIT_FAILURE);
                    }



                    //Else we close off this packet by dumping to our main file
                    //Here we first lock the mutex

                    pthread_mutex_lock(threadData->log_file_mutex);
                    //Then we open the main file creating it if it doesn't exist
                    log_fd = open(OUTPUT_FILE, O_WRONLY | O_CREAT | O_APPEND, 0666);
                    //Keep copying over from temp file to main file
                    while ((bytesRead = read(temp_fd, temp_file_buffer, BUFFER_SIZE)) > 0) {
                        if (write(log_fd, temp_file_buffer, bytesRead) == -1) {
                            perror("Error writing to destination file");
                            close(temp_fd);
                            close(log_fd);
                            exit(EXIT_FAILURE);
                        }
                    }
                    //THen just write the \n and \0 to terminate
                    char *line_terminator = "\n";
                    if (write(log_fd, line_terminator, 1) == -1) {
                        perror("Error writing line terminator");
                        close(temp_fd);
                        close(log_fd);
                        exit(EXIT_FAILURE);
                    }


                    //Then just empty the temporary file
                    if (ftruncate(temp_fd, 0) == -1) {
                        perror("Error truncating file");
                        close(temp_fd); // Close the file descriptor on error
                        exit(EXIT_FAILURE);
                    }
                    //No need for the temp file now so close the fd
                    close(temp_fd);
                    //Now we have to read the entire log file and print the output to the user
                    //Close the current reading mode
                    close(log_fd);
                    //Open it for reading only
                    log_fd = open(OUTPUT_FILE, O_RDONLY);

                }

                //Keep reading  from log file and return over the socket
                while ((bytesRead = read(log_fd, temp_file_buffer, BUFFER_SIZE)) > 0) {
                    //We return the read bytes to the user over the socket
                    //Send the file contents back to the parent
                    if (send(client_socket, temp_file_buffer, bytesRead, 0) == -1) {
                        perror("Failed to send file data back over the socket");
                    }
                }
                //We can close the main file pointer and release the mutex lock
                close(log_fd);
                pthread_mutex_unlock(threadData->log_file_mutex);
            }
        }
    }
    close(client_socket);  // No need for client socket anymore
    threadData->thread_complete_success = true;
    return (void *) threadData;
}

int main(int argc, char *argv[]) {
    int thread_count = 0;
    int client_socket;
    struct addrinfo hints, *address_results, *nodes;
    char s[INET6_ADDRSTRLEN];
    struct sockaddr_storage their_addr;
    socklen_t sin_size;;
    //struct sigaction signal_action;
    int yes = 1;
    bool daemon_mode = false;

    openlog(NULL, 0, LOG_USER);



    // Parse command line arguments
    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = true;
        printf("Daemon Mode enabled \r\n");
    }

    //Set up SIG INT handler
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        fprintf(stderr, "Cannot setup SIGINT!\n");
        return ERROR_RESULT;
    }

    // Setup SIG TERM Handler

    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        fprintf(stderr, "Cannot setup SIGTERM!\n");
        return ERROR_RESULT;
    }

    //Setup Sig Alarm Handler
    if (signal(SIGALRM, alarm_handler) == SIG_ERR) {
        fprintf(stderr, "Cannot setup SIGALARM!\n");
        return ERROR_RESULT;
    }

#if !USE_AESD_CHAR_DEVICE
    //Remove the output file
    if (remove(OUTPUT_FILE) == 0) {
        printf("File '%s' deleted successfully.\n", OUTPUT_FILE);
    }
#endif



    //First get the available addresses on the host at port 9000
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    int rc = getaddrinfo(NULL, PORT, &hints, &address_results);

    if (rc != 0) {
        //Handle Error
        fprintf(stderr, "Failed to get address info Error: %s\n", gai_strerror(rc));
        return ERROR_RESULT;
    }
    //Iterate through and bind
    for (nodes = address_results; nodes != NULL; nodes = nodes->ai_next) {
        if ((server_socket_fd = socket(nodes->ai_family, nodes->ai_socktype,
                                       nodes->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(server_socket_fd, nodes->ai_addr, nodes->ai_addrlen) == -1) {
            close(server_socket_fd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(address_results);

    //Make sure bind was successful
    if (nodes == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        return ERROR_RESULT;
    }

    //since bind was successful now lets start as a daemon
    if (daemon_mode) {
        daemonize();
    }

    //Start listening using socket
    if (listen(server_socket_fd, BACKLOG) == -1) {
        perror("failed to listen to connection");
        return ERROR_RESULT;
    }

//    signal_action.sa_handler = signal_handler;
//    sigemptyset(&signal_action.sa_mask);
//    signal_action.sa_flags = SA_RESTART;
//    if (sigaction(SIGCHLD, &signal_action, NULL) == -1) {
//        perror("sigaction");
//        exit(1);
//    }

    //Initalize the mutex for the logfile
    pthread_mutex_init(&logFileMutex, NULL);
    printf("Currently listening for connections!\n");

    //Setup an alarm
#if !USE_AESD_CHAR_DEVICE
    alarm(10);
#endif

    //Waits for connections
    while (1) {  // main accept() loop
        sin_size = sizeof their_addr;
        client_socket = accept(server_socket_fd, (struct sockaddr *) &their_addr, &sin_size);
        if (client_socket == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                  get_in_addr((struct sockaddr *) &their_addr),
                  s, sizeof s);
        printf("server: got connection from %s \r\n", s);
        syslog(LOG_INFO, "Accepted connection from %s \r\n", s);



        //Create the parameters needed by the thread
        thread_data_t *threadData = (thread_data_t *) malloc(sizeof(thread_data_t));

//        if(threadData == NULL){
//            ERROR_LOG("Failed to allocate memory for thread paramaters");
//            return false;
//
//        }
        //    DEBUG_LOG("Thread param allocation success!");

        //Setup threadData
        threadData->client_socket = client_socket;
        threadData->thread_num = thread_count++;
        threadData->log_file_mutex = &logFileMutex;
        threadData->thread_complete_success = false;

        //Now we create a new node
        thread_node_t *new_node = malloc(sizeof(thread_node_t));

        //Set a pointer to the thread params within the node
        new_node->thread_params = threadData;

        //Create the new thread to handle the connection
        rc = pthread_create(&new_node->thread_id, NULL, thread_function, (void *) threadData);

        //Now put the node into our linked list
        SLIST_INSERT_HEAD(&threadListHead, new_node, entries);


        //Check all threads to see if any are complete
        // Traverse the list and remove elements safely using SLIST_FOREACH_SAFE.
        thread_node_t *currentElement, *tempElement;
        SLIST_FOREACH_SAFE(currentElement, &threadListHead, entries, tempElement) {
            //Check to see if the thread is completed
            if (currentElement->thread_params->thread_complete_success) {
                printf("Cleanup of thread/node %d occuring \r\n", currentElement->thread_params->thread_num);
                //Remove the output file
                char temp_file[256];
                snprintf(temp_file, sizeof(temp_file), "/var/tmp/tempfile_%d.txt",
                         currentElement->thread_params->thread_num);
                if (remove(temp_file) == 0) {
                    printf("File '%s' deleted successfully.\n", temp_file);
                }

                //Join the thread to cleanup its resources
                pthread_join(currentElement->thread_id, NULL);
                // Remove the element safely from the list.
                SLIST_REMOVE(&threadListHead, currentElement, thread_node, entries);
                //Free the thread param data
                free(currentElement->thread_params);
                //Free the node itself
                free(currentElement);

            }
        }
    }

    return 0;

}
