#include<stdio.h>
#include<syslog.h>
#include<errno.h>
#include<stdlib.h>

void main(int argc,char *argv[])
{
	FILE *fp;
	openlog(NULL,0,LOG_USER);
	if(argc!=3)
	{
		syslog(LOG_ERR,	"LOG_ERR: Invalid Number of Arguments: %d",argc);
		exit(1);
	}
	fp  = fopen (argv[1], "w");
	if(fp==NULL){
		syslog(LOG_ERR, "LOG_ERR: Unable to Open/Create File, errno:%d",errno);
		exit(1);
	}

	fputs(argv[2], fp);
	syslog(LOG_DEBUG, "LOG_DEBUG: Writing %s to %s", argv[2], argv[1]);
        fclose(fp);

	return;
}
