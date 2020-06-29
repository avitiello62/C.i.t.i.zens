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
	//starting with a random 32 bytes sk0 and applying a prf (Hmac-Sha256)
	unsigned char *key =Hmac_sha256_on_32_random_bytes();
    
    
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char plaintext[EPHIDS_SIZE] ;
    //setup a dummy plaintext
    memset(plaintext, 0, sizeof plaintext);


    unsigned char ciphertext[EPHIDS_SIZE+10];
    //opening a txt to save all the ephids
    FILE* fp;
    fp=fopen("Data/ephid.txt","w");
    if (fp == NULL)
        return 1;

    //for 14 days
    for (int k=0;k<14;k++){
       /* Encrypt the plaintext */
        int ciphertext_len = encrypt (plaintext, sizeof plaintext, key, iv,ciphertext); 
        //for 1440 minutes
        for (int j=0; j< 1440;j++){
        	//for 16 bytes
            for(int i=0;i<16;i++){
            	//saving in hex code
                fprintf(fp,"%02x",(uint8_t)ciphertext[i+j*16]);
            }
            fprintf(fp,"\n");
        }
        //update the skt+1=sha256(skt)
        size= sizeof key;
        digest_message(key, &key, &size);
        

    }
    


   
    
    fclose(fp);

    

    return 0;
}