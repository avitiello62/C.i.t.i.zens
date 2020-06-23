#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <openssl/aes.h>

unsigned char * Hmac_on_32_random_bytes()
{
  unsigned int seed = 0x00beef00;
  unsigned char  data[40];
  RAND_seed(&seed, sizeof(seed));
  RAND_bytes(data, 32);
  printf("32 random bytes :\n");
  BIO_dump_fp (stdout, (const char *)data, 32);


  
  unsigned char *key = (unsigned char*)"Broadcast Key";
  unsigned char *result;
  int result_len = 32;
  int i;
  static char res_hexstring[32];
  result = HMAC(EVP_sha256(), key, strlen((char *)key), data, strlen((char *)data), NULL, NULL);
  for (i = 0; i < result_len; i++) {
    sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
  }
  printf("Output hmac sha256 :\n");
  BIO_dump_fp (stdout, (const char *)result,32);
  return result;
}



void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

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