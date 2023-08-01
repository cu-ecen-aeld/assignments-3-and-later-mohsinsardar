#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>


#define SERVERPORT "9000"
#define BACKLOG 50
#define BUFFER_SIZE (1000)

bool caught_sigint = false;
bool caught_sigterm = false;
bool time_thread = false;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
char s[BACKLOG][INET6_ADDRSTRLEN];
const char *temp_file = "/var/tmp/aesdsocketdata";

struct f_info {
	int fd;
	pthread_mutex_t mutx;
};

struct thread_param {
	struct f_info *info;
	struct sockaddr addr;
	int socket;
	bool comp_flag;
};

struct thread_node {
	pthread_t id;
	struct thread_param param;
	struct thread_node *next;
};


void *socketThread(void *arg)
{
	int thsockfd = *((int *)arg);
	FILE *fp;
	char sendbuf[BUFFER_SIZE + 1];
	int  readlen = 0;

	long total_bytes = 0;
	char *recv_data = malloc (BUFFER_SIZE);
	openlog("slog", LOG_PID|LOG_CONS, LOG_USER);

	while(1)
	{
		if(caught_sigint || caught_sigterm)
		{
			//Close Sockets, Logging and Exit 
			free(recv_data);
			shutdown(thsockfd, SHUT_RD);
			shutdown(thsockfd, SHUT_WR);
			close(thsockfd);
			syslog(LOG_INFO, "Caught signal, exiting");
			remove("/var/tmp/aesdsocketdata");
 			closelog();
			exit(EXIT_SUCCESS);
		}
		if(recv_data == NULL)
		{
			free(recv_data);
			shutdown(thsockfd, SHUT_RD);
			shutdown(thsockfd, SHUT_WR);
			close(thsockfd);
			syslog(LOG_INFO, "Failed Memory Allocation, exiting");
			closelog();
			exit(EXIT_FAILURE);
		}
		int recv_count = recv(thsockfd, recv_data+total_bytes, BUFFER_SIZE,0);
		if(recv_count < 1)
		{
			free(recv_data);
			shutdown(thsockfd, SHUT_RD);
			shutdown(thsockfd, SHUT_WR);
			close(thsockfd);
			perror("server: socket recv data");
			syslog(LOG_INFO, "Failed Receive Data, exiting %d",recv_count);
			closelog();
			exit(EXIT_FAILURE);
		}
		printf("Recv:%d\n",recv_count);
		total_bytes +=recv_count;

		recv_data = (char*)realloc(recv_data, total_bytes+BUFFER_SIZE);
		if(recv_data == NULL)
		{
			free(recv_data);
			shutdown(thsockfd, SHUT_RD);
			shutdown(thsockfd, SHUT_WR);
			close(thsockfd);
			syslog(LOG_INFO, "Failed Memory Reallocation, exiting");
			closelog();
			exit(EXIT_FAILURE);
		}

		char *total_data  = strchr(recv_data,'\n');
		if(total_data != NULL)
		{	
			pthread_mutex_lock(&lock);
			fp = fopen("/var/tmp/aesdsocketdata", "a+");
			if (fp == NULL) exit(EXIT_FAILURE);
			//perror("server: strchr");
			int total_bytes_recv = (total_data - recv_data)+1;
			//write to file

			int writeLen = fwrite(recv_data, sizeof(char), total_bytes_recv, fp );
			if (writeLen == -1) {
				perror("server: write");
				free(recv_data);
				shutdown(thsockfd, SHUT_RD);
				shutdown(thsockfd, SHUT_WR);
				close(thsockfd);
				syslog(LOG_DEBUG, "write to file failed\n");
				closelog();
				exit(EXIT_FAILURE);
			}

			//printf("Read: recv_data:%x, total_data:%x, total_bytes_recv:%x \n",recv_data, total_data,total_bytes_recv);
			fseek(fp, 0, SEEK_SET);
			while ( (readlen = fread(sendbuf, sizeof(char), BUFFER_SIZE, fp )) )
			{
				printf("Readlen:%d\n",readlen);
				if(readlen == -1 )
				{
					continue;
				}

				if (send(thsockfd, sendbuf, readlen, 0) == -1) 
				{
					syslog(LOG_DEBUG, "Sending Failed\n");
					shutdown(thsockfd, SHUT_RD);
					shutdown(thsockfd, SHUT_WR);
					close(thsockfd);
					closelog();
					free(recv_data);
					exit(EXIT_FAILURE);
				}
			}
			fclose(fp);
			pthread_mutex_unlock(&lock);

			shutdown(thsockfd, SHUT_RD);
			shutdown(thsockfd, SHUT_WR);
			close(thsockfd);
			syslog (LOG_INFO, "Server: Closed connection from %s\n", s[0]);
			free(recv_data);
			recv_data = malloc (BUFFER_SIZE);
			total_bytes = BUFFER_SIZE;
			total_data = 0;
			break;
		}

	}
	free(recv_data);
	close(thsockfd);


	pthread_exit(NULL);
}

#if 0
void *time_write_thread(void *arg)
{
	int tcount = 0;
	char timestr[100];
	time_t ti,reftime=0;
	struct tm *tmp;
	FILE *fp;
	openlog("slog", LOG_PID|LOG_CONS, LOG_USER);

	while(1)
	{
		if(caught_sigint || caught_sigterm)
		{
			//Close Sockets, Logging and Exit 
			syslog(LOG_INFO, "Caught signal, exiting");
			remove("/var/tmp/aesdsocketdata");
 			closelog();
			exit(EXIT_SUCCESS);
		}
		if(time_thread)
			exit(EXIT_SUCCESS);
		tcount++;
		if(tcount >200000)
		{
			tcount = 0;
			ti = time(NULL);
			if(ti >= reftime+10)
			{
				reftime = ti;
				tmp = localtime(&ti);
				if (tmp == NULL) {
					perror("localtime");
					exit(EXIT_FAILURE);
				}
				strncpy(timestr,"timestamp:",11);
				int count = strftime(timestr+10, sizeof(timestr)+10, "%a, %d %b %Y %T %z", tmp);
				if ( count == 0) {
					//if (strftime(timestr+10, sizeof(timestr)-10, "%a, %d %b %Y %T", tmp) == 0) {
					fprintf(stderr, "strftime returned 0");
					exit(EXIT_FAILURE);
				}
				else
				{
					printf("Result string is \"%s\" + count: %d \n", timestr,count);
					timestr[count+10] = '\n';
					pthread_mutex_lock(&lock);
					fp = fopen("/var/tmp/aesdsocketdata", "a+");
					if (fp == NULL) exit(EXIT_FAILURE);
					int writeLen = fwrite(timestr, sizeof(char), count+11, fp );
					fclose(fp);
					pthread_mutex_unlock(&lock);
					if (writeLen == -1)
						exit(EXIT_FAILURE);
					
				}
			}
		}

	}
	pthread_exit(NULL);
}
#endif

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
		printf("timer format");
		return;
	}

	int len = sprintf(buf2, "timestamp:%s\n", buf1);
	printf("timestamp:%s", buf1);
	if (pthread_mutex_lock(&param->info->mutx) != 0) {
		printf("Error %d (%s) locking thread data!\n", errno, strerror(errno));
	} else {
		lseek(param->info->fd, 0, SEEK_END);
		write(param->info->fd, buf2, len);
		if (pthread_mutex_unlock(&param->info->mutx) != 0)
			printf("Error %d (%s) unlocking thread data!\n", errno, strerror(errno));
	}
}

static void signal_handler (int signal_number)
{
	if(signal_number == SIGINT)
	{
		caught_sigint = true;
		time_thread = true;
	}
	else if (signal_number == SIGTERM)
	{
		caught_sigterm = true;
		time_thread = true;
	}
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int  sockfd, new_fd, status, yes=1,id=0;
	struct addrinfo hints, *res , *p;
	struct sigaction sa;
	pthread_t tid[BACKLOG];
	//pthread_t timeid;
	int clock_id = CLOCK_REALTIME;
	timer_t timerid = 0;
    	struct sigevent sev;
	//bool timeflag = true;
	struct f_info _finfo;
	struct thread_param td;


	struct sockaddr_storage their_addr;
	socklen_t sin_size;

	openlog("slog", LOG_PID|LOG_CONS, LOG_USER);

	memset(&sev, 0, sizeof(struct sigevent));
	memset(&td, 0, sizeof(struct thread_param));	
	pthread_mutex_init(&lock, NULL);

	_finfo.fd = open(temp_file, O_RDWR | O_CREAT | O_TRUNC, 0664);
	if (_finfo.fd == -1) {
		syslog(LOG_ERR, "File Opening error: %s", strerror(errno));
		printf("File Opening errno: %d, meaning: %s", errno, strerror(errno));
		exit(-1);
	}

	if (pthread_mutex_init(&_finfo.mutx, NULL) != 0) {
		syslog(LOG_ERR, "Mutex Error: %s", strerror(errno));
		printf("Mutex Errno: %d, meaning: %s", errno, strerror(errno));
		exit(-1);
	}

	td.info = &_finfo;


	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	status = getaddrinfo(NULL,SERVERPORT,&hints,&res);
	if(status != 0)
	{
		//fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		syslog(LOG_ERR,"Getaddrinfo Error: (%s) ", gai_strerror(status));
 		closelog();
		return -1;
	}

	for(p = res; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("server: socket");
			syslog(LOG_ERR,"Server Socket Error");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
					sizeof(int)) == -1) {
			perror("setsockopt");
			syslog(LOG_ERR,"Server setsocketopt Error");
			closelog();
			exit(EXIT_FAILURE);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			//close(sockfd);
			perror("server: bind");
			syslog(LOG_ERR,"Server Bind Error");
			continue;
		}

		break;
	}
	freeaddrinfo(res); // all done with this structure

	if (p == NULL)  {
		//fprintf(stderr, "server: failed to bind\n");
		syslog(LOG_ERR,"Server failed to Bind");
		exit(EXIT_FAILURE);
	}

	if(argc>1)
		if (strncmp("-d", argv[1], 2) == 0) 
		{
			status = fork();
			if(status == -1)
			{
				syslog(LOG_ERR,"Failed to run as deamon");
				closelog();
				return -1;
			}
			else if(status == 0)
				;
			else
				return 0;
		}
	
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = signal_handler;
	if(sigaction(SIGTERM, &sa, NULL) != 0)
	{
		syslog(LOG_ERR,"Error %d(%s) in registering SIGTERM Signal",errno,strerror(errno));
		closelog();
		return -1;
	}
	if(sigaction(SIGINT, &sa, NULL) )
	{
		syslog(LOG_ERR,"Error %d(%s) in registering SIGINT Signal",errno,strerror(errno));
		closelog();
		return -1;
	}

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_value.sival_ptr = &td;
	sev.sigev_notify_function = timer_thread;
	if (timer_create(clock_id, &sev, &timerid) != 0) {
		syslog(LOG_ERR,"Create Timer Error!");
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

	if (listen(sockfd, BACKLOG) == -1) {
		//perror("listen");
		syslog(LOG_ERR,"Server failed to Listen");
		exit(EXIT_FAILURE);
	}


	printf("server: waiting for connections...\n");



	while(1) {  // main accept() loop

		if(caught_sigint || caught_sigterm)
		{
			//Close Sockets, Logging and Exit 
			shutdown(sockfd, SHUT_RD);
			shutdown(sockfd, SHUT_WR);
			close(sockfd);
			syslog(LOG_INFO, "Caught signal, exiting");
			remove(temp_file);
 			closelog();
			exit(EXIT_FAILURE);
		}

		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s[id], sizeof s[id]);
		//printf("Server: Accepted connection from %s\n", s);
		syslog (LOG_INFO, "Server: Accepted connection from %s\n", s[id]);
		if( pthread_create(&tid[id++], NULL, socketThread, &new_fd) != 0 )
		{
			printf("Failed to create thread\n");

		}
		else
		{
			pthread_join(tid[id-1],NULL);
		}
		if(id>=BACKLOG)
			break;
		/*if(timeflag == true)
		{
			if( pthread_create(&timeid, NULL, time_write_thread, &status) != 0 )
			{
				printf("Failed to create thread\n");

			}
			else
			{
				//pthread_join(timeid,NULL);
			}
			timeflag = false;
		}*/

	}
	//pthread_join(timeid,NULL);

	shutdown(sockfd, SHUT_RD);
	shutdown(sockfd, SHUT_WR);
	close(sockfd);
	remove(temp_file);
	closelog();
	return 0;
}
