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


#define SERVERPORT "9000"
#define BACKLOG 10
#define BUFFER_SIZE (1000)

bool caught_sigint = false;
bool caught_sigterm = false;

static void signal_handler (int signal_number)
{
	if(signal_number == SIGINT)
		caught_sigint = true;
	else if (signal_number == SIGTERM)
		caught_sigterm = true;
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
	int  sockfd, new_fd, status, yes=1, readlen = 0;;
	struct addrinfo hints, *res , *p;
	struct sigaction sa;
	FILE *fp;
	char sendbuf[BUFFER_SIZE + 1];

	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];

	openlog("slog", LOG_PID|LOG_CONS, LOG_USER);


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
			exit(1);
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
		exit(1);
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
	

	if (listen(sockfd, BACKLOG) == -1) {
		//perror("listen");
		syslog(LOG_ERR,"Server failed to Listen");
		exit(1);
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
			remove("/var/tmp/aesdsocketdata");
 			closelog();
			exit(-1);
		}
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		//remove("/var/tmp/aesdsocketdata");
		inet_ntop(their_addr.ss_family,
				get_in_addr((struct sockaddr *)&their_addr),
				s, sizeof s);
		//printf("Server: Accepted connection from %s\n", s);
		syslog (LOG_INFO, "Server: Accepted connection from %s\n", s);

		long total_bytes = 0;
		char *recv_data = malloc (BUFFER_SIZE);

		while(1)
		{
			if(recv_data == NULL)
			{
				free(recv_data);
				shutdown(sockfd, SHUT_RD);
				shutdown(sockfd, SHUT_WR);
				close(sockfd);
				syslog(LOG_INFO, "Failed Memory Allocation, exiting");
				closelog();
				exit(-1);
			}
			int recv_count = recv(new_fd, recv_data+total_bytes, BUFFER_SIZE,0);
			if(recv_count < 1)
			{
				free(recv_data);
				shutdown(sockfd, SHUT_RD);
				shutdown(sockfd, SHUT_WR);
				close(sockfd);
				perror("server: socket recv data");
				syslog(LOG_INFO, "Failed Receive Data, exiting %d",recv_count);
				closelog();
				exit(-1);
			}
			printf("Recv:%d\n",recv_count);
			total_bytes +=recv_count;
			
			recv_data = (char*)realloc(recv_data, total_bytes+BUFFER_SIZE);
			if(recv_data == NULL)
			{
				free(recv_data);
				shutdown(sockfd, SHUT_RD);
				shutdown(sockfd, SHUT_WR);
				close(sockfd);
				syslog(LOG_INFO, "Failed Memory Reallocation, exiting");
				closelog();
				exit(-1);
			}

	       		char *total_data  = strchr(recv_data,'\n');
			if(total_data != NULL)
			{	
				fp = fopen("/var/tmp/aesdsocketdata", "a+");
				if (fp == NULL) return -1;
				//if (fp == -1) return -1;
				//perror("server: strchr");
				int total_bytes_recv = (total_data - recv_data)+1;
				//write to file

				int writeLen = fwrite(recv_data, sizeof(char), total_bytes_recv, fp );
				if (writeLen == -1) {
					perror("server: write");
					free(recv_data);
					shutdown(sockfd, SHUT_RD);
					shutdown(sockfd, SHUT_WR);
					close(sockfd);
					syslog(LOG_DEBUG, "write to file failed\n");
					closelog();
					exit(-1);
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

					if (send(new_fd, sendbuf, readlen, 0) == -1) 
					{
						syslog(LOG_DEBUG, "Sending Failed\n");
						shutdown(sockfd, SHUT_RD);
						shutdown(sockfd, SHUT_WR);
						close(sockfd);
						closelog();
						free(recv_data);
						exit(-1);
					}
				}
				shutdown(new_fd, SHUT_RD);
				shutdown(new_fd, SHUT_WR);
				close(new_fd);
				syslog (LOG_INFO, "Server: Closed connection from %s\n", s);
				free(recv_data);
				recv_data = malloc (BUFFER_SIZE);
				total_bytes = BUFFER_SIZE;
				total_data = 0;
				break;
			}
			
		}
		free(recv_data);
		close(new_fd);
	}

	shutdown(sockfd, SHUT_RD);
	shutdown(sockfd, SHUT_WR);
	close(sockfd);
	closelog();
	return 0;
}
