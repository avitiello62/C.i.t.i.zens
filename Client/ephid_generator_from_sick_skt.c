#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <openssl/aes.h>
#include "./lib_cyb.h"


#define EPHIDS_SIZE (1440*16*14)

int main (int argc, char* argv[])
{
    int size;

    //opening the files that contains the skt of a sick person (in hex convention)
    FILE* fp1;
    fp1=fopen("Data/sick_skt.txt","r");
    if (fp1 == NULL){
        return 1; 
    }
    
    unsigned char hex_data[64];
    unsigned char c1,c2;
    int i=0;
    unsigned char sum;
    //convertion from char to hex and from hex to unsigned int
    printf("Skt:\t");
    for(i=0;i<64/2;i++)
    {
            c1 = ascii_to_hex(fgetc(fp1));
            c2 = ascii_to_hex(fgetc(fp1));
            sum = c1<<4 | c2;
            hex_data[i] = sum;
            printf("%02x",sum);
    }
    printf("\n");
	 //starting from a sk0 and applying a prf (Hmac-Sha256) 
    unsigned char* data=(unsigned char*) hex_data;
    unsigned char *b_key = (unsigned char*)"Broadcast Key";
  	unsigned char *key;
  	int key_len = 32;
  	
  	static char res_hexstring[32];
  	key = HMAC(EVP_sha256(), b_key, strlen((char *)b_key), data, strlen((char *)data), NULL, NULL);
  	for (int i = 0; i < key_len; i++) {
    	sprintf(&(res_hexstring[i * 2]), "%02x", key[i]);
  	}
  	printf("\nOutput hmac-sha256:\t");
  	for(i=0;i<32;i++)
    	printf("%02x",(uint8_t)key[i]);
    printf("\n");
 
     /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char plaintext[EPHIDS_SIZE] ;
	//setup a dummy plaintext
    memset(plaintext, 0, sizeof plaintext);


    unsigned char ciphertext[EPHIDS_SIZE+10];
    //opening a txt to save all the ephids
    FILE* fp2;

    fp2=fopen("ephid_sick.txt","w");
    if (fp2 == NULL)
        return 1;
    //for 14 days
    for (int k=0;k<14;k++){
       /* Encrypt the plaintext */
        int ciphertext_len = encrypt (plaintext, sizeof plaintext, key, iv,
                              ciphertext); 
        //for 1440 minutes
        for (int j=0; j< 1440;j++){
        	//for 16 bytes
            for(int i=0;i<16;i++){
            	//saving in hex convention
                fprintf(fp2,"%02x",(uint8_t)ciphertext[i+j*16]);
            }
            fprintf(fp2,"\n");
        }
        //update the skt+1=sha256(skt)
        size= sizeof key;
        digest_message(key, &key, &size);
        

    }
    


   
    
    fclose(fp2);

    

    return 0;
}