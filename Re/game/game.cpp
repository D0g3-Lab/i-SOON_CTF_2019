#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#define BOOL int
#define FALSE 1
#define TRUE 0
 
typedef struct node
{
    int col;
    int row;
    int value[10];
} Node;
 
int findvalue(int sudoku[9][9], Node * node);
BOOL general_inspection(int sudoku[9][9]);
int blank_num(int sudoku[9][9]);
Node * mem_alloc(int num_of_empty);
void trace(int sudoku[9][9], Node * node_stack, int num_of_empty);
void check(int sudoku[9][9]);
void check1(char *a);
int check2(char *a);
void check3(char *a);
 

int sudoku[9][9] = {{1,0,5,3,2,7,0,0,8},
                        {8,0,9,0,5,0,0,2,0},
                        {0,7,0,0,1,0,5,0,3},
                        {4,9,0,1,0,0,3,0,0},
                        {0,1,0,0,7,0,9,0,6},
                        {7,0,3,2,9,0,4,8,0},
                        {0,6,0,5,4,0,8,0,9},
                        {0,0,4,0,0,1,0,3,0},
                        {0,2,1,0,3,0,7,0,4}
};
                        
int arange[9][9] = {{1,0,5,3,2,7,0,0,8},
                        {8,0,9,0,5,0,0,2,0},
                        {0,7,0,0,1,0,5,0,3},
                        {4,9,0,1,0,0,3,0,0},
                        {0,1,0,0,7,0,9,0,6},
                        {7,0,3,2,9,0,4,8,0},
                        {0,6,0,5,4,0,8,0,9},
                        {0,0,4,0,0,1,0,3,0},
                        {0,2,1,0,3,0,7,0,4}
};

int D0g3[9][9] = {{1,0,5,3,2,7,0,0,8},
                        {8,0,9,0,5,0,0,2,0},
                        {0,7,0,0,1,0,5,0,3},
                        {4,9,0,1,0,0,3,0,0},
                        {0,1,0,0,7,0,9,0,6},
                        {7,0,3,2,9,0,4,8,0},
                        {0,6,0,5,4,0,8,0,9},
                        {0,0,4,0,0,1,0,3,0},
                        {0,2,1,0,3,0,7,0,4}
};

int key[42];
int key1[42];
 
int main(void)
{
	
	char a[42];
	int i;
	printf("input your flag:");

	gets(a);
	
    int num_of_empty;
    Node * node_stack;
 
    if(general_inspection(sudoku))
    {
        printf("error");
        check(sudoku);
       return 0;
   }
    num_of_empty = blank_num(sudoku);
    node_stack = mem_alloc(num_of_empty);
    trace(sudoku, node_stack, num_of_empty);
    check(sudoku);
 	check1(a);
	check3(a);
    return 0;
}
 
BOOL general_inspection(int sudoku[9][9])
{
    int temp[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int i, j, m, n;
    for(i=0; i<9; i++)
        for(j=0; j<9; j++)
            if(sudoku[i][j]!=0)
            {
                
                for(m=0; m<10; m++)
                    temp[m] = 0;
                for(m=0; m<9; m++)
                    if(sudoku[i][m]!=0)
                    {
                        if(temp[sudoku[i][m]]==0)
                            temp[sudoku[i][m]] = 1;
                        else
                            return FALSE;
                    }
                
                for(m=0; m<10; m++)
                    temp[m] = 0;
                for(m=0; m<9; m++)
                    if(sudoku[m][j]!=0)
                    {
                        if(temp[sudoku[m][j]]==0)
                            temp[sudoku[m][j]] = 1;
                        else
                            return FALSE;
                    }
                
                for(m=0; m<10; m++)
                    temp[m] = 0;
                for(m=0; m<3; m++)
                    for(n=0; n<3; n++)
                        if(sudoku[i/3*3+m][j/3*3+n]!=0)
                        {
                            if(temp[sudoku[i/3*3+m][j/3*3+n]]==0)
                                temp[sudoku[i/3*3+m][j/3*3+n]] = 1;
                            else
                                return FALSE;
                        }
            }
    return TRUE;
}
 
int blank_num(int sudoku[9][9])
{
    int i, j, num = 0;
    for(i=0; i<9; i++)
        for(j=0; j<9; j++)
            if(sudoku[i][j]==0)
                num++;
    return num;
}
 
Node * mem_alloc(int num_of_empty)
{
    Node * node_stack = (Node *)malloc(sizeof(struct node) * num_of_empty);
    if(node_stack==NULL)
    {
        printf("error\n");
        exit(1);
    }
    return node_stack;
}
 
 
void trace(int sudoku[9][9], Node * node_stack, int num_of_empty)
{
    int i, j, index, k = 0;
    while(num_of_empty)
    {
        for(i=0; i<9; i++)
        {
            for(j=0; j<9; j++)
            {
                if(sudoku[i][j]==0)
                {
                    (node_stack + k)->col = i;
                    (node_stack + k)->row = j;
                    sudoku[i][j] = findvalue(sudoku, node_stack+k);
                    if(sudoku[i][j]==-1)
                    {
                        sudoku[i][j] = 0;
                        k--;
                        while((node_stack + k)->value[0]==0)
                        {
                            
                            if(k==0)
                            {
                                printf("game over£¡\n");
                                
                                exit(1);
                            }
                            sudoku[(node_stack + k)->col][(node_stack + k)->row] = 0;
                            num_of_empty++;
                            k--;
                        }
                        for(index=1; index<10; index++)
                            if((node_stack + k)->value[index]==0)
                            {
                                sudoku[(node_stack + k)->col][(node_stack + k)->row] = index;
                                (node_stack + k)->value[index] = 1;
                                (node_stack + k)->value[0]--;
                                break;
                            }
                        num_of_empty++;
                        i = (node_stack + k)->col;
                        j = (node_stack + k)->row;
                    }
                    k++;
                    num_of_empty--;
                }
            }
        }
    }
    free(node_stack);
    node_stack=NULL;
}
 
int findvalue(int sudoku[9][9], Node * node)
{
    int m, n, i = node->col, j = node->row;
    for(m=0; m<10; m++)
        node->value[m] = 0;
    for(m=1; m<10; m++)
    {
        node->value[sudoku[i][m-1]] = 1;
        node->value[sudoku[m-1][j]] = 1;
    }
    for(m=0; m<3; m++)
        for(n=0; n<3; n++)
            node->value[sudoku[i/3*3+m][j/3*3+n]] = 1;
 
    node->value[0] = 0;
    for(m=1; m<10; m++)
        if(node->value[m]==0)    node->value[0]++;
    for(m=1; m<10; m++)
        if(node->value[m]==0)
        {
            node->value[m] = 1;
            node->value[0]--;
            break;
        }
 
    if(m==10)
        return -1;
    else
        return m;
}

void check (int sudoku[9][9])
{
    
    int i, j;
    int count = 0;
    for(i=0; i<9; i++)
    {
        for(j=0; j<9; j++)
        {
        	
		}
        
    }
}

 void check1(char *a){
 	int i,j = 0;
 	for(i = strlen(a)/2,j = 0;j<strlen(a)/2;j++,i++){
	 	char temp;
	 	temp = a[i];
	 	a[i] = a[j];
	 	a[j] = temp; 
	 }
 	for(i = 0;i<strlen(a);i=i+2){
 		char temp;
 		temp = a[i];
 		a[i] = a[i+1];
 		a[i+1] = temp;
	 }
 	for(i =0;i<strlen(a);i++)
 		a[i] = (a[i]^12)-20 ;  	
 }

 int check2(char *a)
 {
 	int theseus[42];
 	int i,j;
 	int count = 0;
 	int flag = 1; 
	for (i = 0;i<strlen(a);i++)
	{
		theseus[i] = a[i]-48;	
	}
	printf("\n");
	 	
 	for(i = 0;i < 9;i++){
 		for(j = 0;j<9;j++){
 			if(D0g3[i][j] == 0){
 				D0g3[i][j] = theseus[count];
 				count++;
			 }
	 	}
	}
	
	for(i = 0;i<9;i++)
	{
		for(j = 0;j<9;j++)
		{
			if(D0g3[i][j]!=sudoku[i][j]){
				flag = 0;
				break;
			}
				
		}
		if(flag == 0)
			break;
	}
	
	
	return flag;
 }
 
 void check3(char *a){
 	int flag = check2(a);
 	if(flag == 0)
	 	printf("error!\n");
 		
 	else
 		printf("you get it!\n");
 }
