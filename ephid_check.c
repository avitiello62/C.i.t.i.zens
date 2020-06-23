

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	int i=0;
    FILE * fp1;
    FILE * fp2;
    char * line1 = NULL;
    size_t len1 = 0;
    ssize_t read1;
    char * line2 = NULL;
    size_t len2 = 0;
    ssize_t read2;

    fp1 = fopen("ephid.txt", "r");
    if (fp1 == NULL)
        exit(EXIT_FAILURE);
    
    while ((read1 = getline(&line1, &len1, fp1)) != -1) {
    	fp2 = fopen("ephid_sick.txt", "r");
		if (fp2 == NULL)
        	exit(EXIT_FAILURE);
        while ((read2 = getline(&line2, &len2, fp2)) != -1)
        	if(strcmp(line1,line2)==0){
        		printf("\n Malato = %d\t",++i);
        		printf("%s\n",line1);
        	}
    }

    fclose(fp1);
    fclose(fp2);
    exit(EXIT_SUCCESS);
}