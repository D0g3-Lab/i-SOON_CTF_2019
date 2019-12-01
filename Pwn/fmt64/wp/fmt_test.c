#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int main(void){
	//init
	setbuf(stdout,0);
	setbuf(stdin,0);
	setbuf(stderr,0);
	printf("Hello,I am a computer Repeater updated.\nAfter a lot of machine learning,I know that the essence of man is a reread machine!\n");
	printf("So I'll answer whatever you say!\n");
	
	char buf[257];
	char format[300];
	unsigned int len1 = 0;
	while(1){
		alarm(3);
		memset(buf,0,sizeof(char)*257);
		memset(format,0,sizeof(char)*300);
		printf("Please tell me:");
		read(0,buf,256);
		sprintf(format,"Repeater:%s\n",buf);
		len1 = strlen(format);
		if(len1 > 270){
			printf("what you input is really long!");
			exit(0);
		}
		printf(format);
	}
	printf("game over!\n");
	return 0;
}