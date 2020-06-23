#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <openssl/aes.h>
#include "./lib_cyb.h"

int main (void)
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = Hmac_on_32_random_bytes();

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char plaintext[1440*16] ;

    memset(plaintext, 0, sizeof plaintext);
    //BIO_dump_fp (stdout, (const char *)plaintext, 1440);

        //(unsigned char *)"The quick brown fox jumps over the lazy dog";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */



    unsigned char ciphertext[2000*16];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[2000*16];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, sizeof plaintext, key, iv,
                              ciphertext);

    /* Do something useful with the ciphertext here 
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    */
    FILE* ephid;

    ephid=fopen("ephid.txt","w");
    for (int j=0; j< 1440;j++){
        for(int i=0;i<16;i++){
            fprintf(ephid,"%02x",(uint8_t)ciphertext[i+j*16]);
        }
        fprintf(ephid,"\n");
    }
    fclose(ephid);
    /* Decrypt the ciphertext */
    //decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                //decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    //decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    //printf("Decrypted text is:\n");
    
    //BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

    return 0;
}