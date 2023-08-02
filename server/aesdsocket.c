#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
#include <signal.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

#define PORT 9000
#define BUF_SIZE 65535

//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("socket: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("socket ERROR: " msg "\n" , ##__VA_ARGS__)

const char *tmp_file = "/var/tmp/aesdsocketdata";
volatile bool caught_sig = false;

struct file_info {
  int fd;
  pthread_mutex_t mtx;
};

struct thread_param {
  struct file_info *info;
  struct sockaddr address;
  int socket;
  bool complete_flag;
};

struct thread_node {
  pthread_t id;
  struct thread_param param;
  struct thread_node *next;
};



static void signal_handler(int signal_number)
{
    if (signal_number == SIGTERM || signal_number == SIGINT)
        caught_sig = true;
}

static void set_signal_handler()
{
    struct sigaction new_action;

    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler = signal_handler;
    if (sigaction(SIGTERM, &new_action, NULL) != 0) {
        ERROR_LOG("Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        syslog(LOG_ERR, "Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        exit(-1);
    }
    if (sigaction(SIGINT, &new_action, NULL) != 0) {
        ERROR_LOG("Error %d (%s) registering for SIGINT", errno, strerror(errno));
        syslog(LOG_ERR, "Error %d (%s) registering for SIGINT", errno, strerror(errno));
        exit(-1);
    }
}

static void *handle_connection(void *arg)
{
    struct thread_param *param = (struct thread_param *)arg;
    char ipstr[INET6_ADDRSTRLEN];;
    char *buffer;
    ssize_t recv_len, read_len;

    buffer = (char *)malloc(BUF_SIZE);
    memset(buffer, 0, BUF_SIZE);
    while (true) {
        if (param->address.sa_family == AF_INET6) { // AF_INET6
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&param->address;
            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
        } else {
            struct sockaddr_in *s = (struct sockaddr_in *)&param->address;
            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
        }

        syslog(LOG_DEBUG, "Accepted connection from %s", ipstr);
        DEBUG_LOG("Accepted connection from %s", ipstr);
        ssize_t start = 0;
        do {
            int len = recv(param->socket, &buffer[start], BUF_SIZE, 0);
            if (len == 0) {
                free(buffer);
                close(param->socket);
                syslog(LOG_DEBUG, "Closed connection from %s", ipstr);
                DEBUG_LOG("Closed connection from %s", ipstr);
                param->complete_flag = true;
                return NULL;
            }

            start += len;
        } while (buffer[start-1] != '\n');
        recv_len = start;

        DEBUG_LOG("len=%ld, packet=%s", recv_len, buffer);
        if (pthread_mutex_lock(&param->info->mtx) != 0)
            ERROR_LOG("pthread_mutex_lock failed");

        lseek(param->info->fd, 0, SEEK_END);
        write(param->info->fd, buffer, recv_len);
        if (pthread_mutex_unlock(&param->info->mtx) != 0)
            ERROR_LOG("pthread_mutex_unlock failed");
        memset(buffer, 0, recv_len);

        lseek(param->info->fd, 0, SEEK_SET);
        start = 0;
        while (true) {
            while (true) {
                read_len = read(param->info->fd, &buffer[start], 1);
                if (buffer[start] == '\n' || read_len <= 0)
                    break;
                start++;
            }
            if (buffer[start] == '\n') {
                read_len = start + 1;
                DEBUG_LOG("read length is %ld, contents: %s", read_len, buffer);
                ssize_t send_len = send(param->socket, buffer, read_len, 0);
                memset(buffer, 0, send_len);
                start = 0;
            } else
                break;
        }
    }
}

static void timer_thread(union sigval sigval)
{
    struct thread_param *param = (struct thread_param *)sigval.sival_ptr;
    time_t t;
    struct tm *tmp;
    char buf1[100];
    char buf2[120];

    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    t = time(NULL);
    tmp = localtime(&t);

    if (strftime(buf1, sizeof(buf1), "%F %T", tmp) == 0){
        ERROR_LOG("timer format");
        return;
    }

    int len = sprintf(buf2, "timestamp:%s\n", buf1);
    DEBUG_LOG("timestamp:%s", buf1);
    if (pthread_mutex_lock(&param->info->mtx) != 0) {
        ERROR_LOG("Error %d (%s) locking thread data!\n", errno, strerror(errno));
    } else {
        lseek(param->info->fd, 0, SEEK_END);
        write(param->info->fd, buf2, len);
        if (pthread_mutex_unlock(&param->info->mtx) != 0)
            ERROR_LOG("Error %d (%s) unlocking thread data!\n", errno, strerror(errno));
    }
}

static void socket_service(int server_fd)
{
    int addrlen = 0;
    struct file_info finfo;
    int clock_id = CLOCK_REALTIME;
    timer_t timerid = 0;
    struct sigevent sev;
    struct thread_param td;

    memset(&sev, 0, sizeof(struct sigevent));
    memset(&td, 0, sizeof(struct thread_param));

    finfo.fd = open(tmp_file, O_RDWR | O_CREAT | O_TRUNC, 0664);
    if (finfo.fd == -1) {
        syslog(LOG_ERR, "Open file error: %s", strerror(errno));
        ERROR_LOG("Open file errno: %d, meaning: %s", errno, strerror(errno));
        exit(-1);
    }

    if (pthread_mutex_init(&finfo.mtx, NULL) != 0) {
        syslog(LOG_ERR, "init mutex error: %s", strerror(errno));
        ERROR_LOG("init mutex errno: %d, meaning: %s", errno, strerror(errno));
        exit(-1);
    }

    td.info = &finfo;
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = &td;
    sev.sigev_notify_function = timer_thread;
    if (timer_create(clock_id, &sev, &timerid) != 0) {
        ERROR_LOG("timer_creat error!");
        exit(-1);
    } else {
        struct itimerspec its = {
            .it_value.tv_sec  = 10,
            .it_value.tv_nsec = 0,
            .it_interval.tv_sec = 10,
            .it_interval.tv_nsec = 0
        };

        timer_settime(timerid, 0, &its, NULL);
    }

    struct thread_node *head = malloc(sizeof(struct thread_node));
    memset(head, 0, sizeof(struct thread_node));
    DEBUG_LOG("server is listening at port: %d", PORT);
    while (!caught_sig) {
        struct thread_node *node = (struct thread_node *)malloc(sizeof(struct thread_node));
        memset(node, 0, sizeof(struct thread_node));
        struct thread_param *params = &node->param;
        if ((params->socket
             = accept(server_fd, &params->address, (socklen_t*)&addrlen))
            < 0) {
            free(node);
            if (caught_sig)
                break;
            syslog(LOG_ERR, "accept failed");
            ERROR_LOG("Error %d (%s) accept", errno, strerror(errno));
            exit(-1);
        }

        params->info = &finfo;
        params->complete_flag = false;
        pthread_create(&node->id, NULL, handle_connection, params);
        struct thread_node *tmp_head = head;
        while (tmp_head->next != NULL) {
            struct thread_node* node = tmp_head->next;
            if (node->param.complete_flag) {
                pthread_join(node->id, NULL);
                tmp_head->next = node->next;
                free(node);
            } else
                tmp_head = tmp_head->next;
        }
        tmp_head->next = node;
    }

    while (head->next != NULL) {
        struct thread_node* node = head->next;
        pthread_join(node->id, NULL);
        head->next = node->next;
        free(node);
    }
    free(head);

    remove(tmp_file);
}

int main(int argc, char **argv)
{
    int server_fd;
    pid_t pid;
    int i;
    struct sockaddr_in address;
    int opt = 1;

    openlog(NULL, 0, LOG_USER);

    server_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        syslog(LOG_ERR, "Invalid number of arguments: %d", server_fd);
        exit(-1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        syslog(LOG_ERR, "setsockopt failed");
        exit(-1);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        syslog(LOG_ERR, "bind failed");
        exit(-1);
    }

    if ((argc > 1) && (strcmp(argv[1], "-d") == 0)) {
        DEBUG_LOG("Server will be put on daemon");
        pid = fork ();
        if (pid == -1)
            return -1;
        else if (pid != 0) {
            DEBUG_LOG("parent exits");
            syslog(LOG_DEBUG, "parent exits");
            closelog();
            exit(EXIT_SUCCESS);
        }

        /* create new session and process group */
        if (setsid () == -1)
            return -1;
        /* set the working directory to the root directory */
        if (chdir ("/") == -1)
            return -1;
        /* close all fid 0, 1, 2 */
        for (i = 0; i < 3; i++)
            close(i);
        /* redirect fd's 0,1,2 to /dev/null */
        open("/dev/null", O_RDWR);
        /* stdin */
        dup(0);
        /* stdout */
        dup(0);
        /* stderror */
    }

    if (listen(server_fd, 3) < 0) {
        syslog(LOG_ERR, "listen failed");
        exit(-1);
    }

    set_signal_handler();

    socket_service(server_fd);

    syslog(LOG_DEBUG, "Caught signal, exiting");
    shutdown(server_fd, SHUT_RDWR);
    syslog(LOG_DEBUG, "Successfully cleaned up");
    closelog();
    DEBUG_LOG("Successfully cleaned up");
    return 0;
}
