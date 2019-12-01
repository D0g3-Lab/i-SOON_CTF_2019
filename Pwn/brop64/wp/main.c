#include <stdio.h>
#include <unistd.h>
#include <string.h>
int i;
int repeater();
int main(void){
	setbuf(stdin,0);
	setbuf(stdout,0);
	setbuf(stderr,0);
    printf("Hello,I am a computer Repeater updated.\nAfter a lot of machine learning,I know that the essence of man is a reread machine!\n");
	printf("So I'll answer whatever you say!\n");

	repeater();
	printf("Goodbye!\n");
	return 0;
}

int repeater(){
	char buf[200];
	printf("First Please tell me:");
	memset(buf,0,200);
	read(STDIN_FILENO,buf,1024);
	if(!strcmp(buf,"If there is a chance,I won't make any mistake!\n")){
		printf("Wish you happy everyday!\n");
		return 0;
	}
	printf("Repeater:");
	write(STDOUT_FILENO,buf,strlen(buf));

	//putchar(10);
	return 0;
}