#ifndef INC_LIB_CYB_H_
#define INC_LIB_CYB_H_


unsigned char * Hmac_on_32_random_bytes();
void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

#endif /* INC_LIB_CYB_H*/