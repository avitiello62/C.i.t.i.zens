#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int main(void)
{
	int i=0;
    FILE * fp1;
    FILE * fp2;
    char buffer1[40];
    char buffer2[40];
    //open list of all ephids collected from contact
    fp1 = fopen("contact_list.txt", "r");
    if (fp1 == NULL)
        return 1;
    //for each ephid
    while (fgets (str, 33, fp1)!=NULL) {
    	//open the file with all sick ephids 
    	fp2 = fopen("ephid_sick.txt", "r");
		if (fp2 == NULL)
        	return 1;
        while (fgets (str2, 33, fp2)!=NULL)
        	//count how much corrispondence there are
        	if(strcmp(str,str2)==0){
        		printf("\n Malato = %d\t",++i);
        		printf("%s\n",str);
        	}
    }

    fclose(fp1);
    fclose(fp2);
    return 0;
}



