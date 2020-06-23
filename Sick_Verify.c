#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <openssl/aes.h>
#include "./lib_cyb.h"

int main (int argc, char* argv[])
{
    
	 //starting from a skt
    if(argc<=1){
        return 1;
    }
	unsigned char* key=(unsigned char *)argv[1];
 
     /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char plaintext[1440*16*14] ;

    memset(plaintext, 0, sizeof plaintext);


    unsigned char ciphertext[1450*16*14];
    FILE* ephid;

    ephid=fopen("ephid_sick.txt","w");

    for (int k=0;k<14;k++){
       /* Encrypt the plaintext */
        int ciphertext_len = encrypt (plaintext, sizeof plaintext, key, iv,
                              ciphertext); 
        for (int j=0; j< 1440;j++){
            for(int i=0;i<16;i++){
                fprintf(ephid,"%02x",(uint8_t)ciphertext[i+j*16]);
            }
            fprintf(ephid,"\n");
        }
        int size= sizeof key;
        digest_message(key, &key, &size);
        

    }
    


   
    
    fclose(ephid);

    

    return 0;
}