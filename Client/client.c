#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#define LEN 1024
#define PORT 3000

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "Cert/cacert.pem"
#define CADIR NULL
#define CERTFILE "Cert/medicalcentercert.pem"

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
 
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);
 
        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
 
    return ok;
}


main(int argc, char **argv){
	char CAfile[]="Cert/medicalcentercert.pem";
	char secretkey[]="Cert/medicalcenterkey.pem";
	char buff_out[]="Ciao Sever";
	char buff_in[LEN];
	SSL *ssl;
	SSL_CTX *ctx;
	int sd, cnt;
	X509 * server_cert;
	struct sockaddr_in servaddr;
	char * str;

	FILE* fp1;
	fp1=fopen("Data/sick_skt.txt","w");
		if (fp1 == NULL){
        return 1; 
    }

	if (argc != 2) {
		fprintf(stderr,"usage: %s <IPaddress>\n", argv[0]);
		exit (1);
	}
	if ( (sd = socket(AF_INET, SOCK_STREAM, 0)) <0){
		perror("opening socket");
		exit(1);
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0) {
		perror("inet_pton error");
		exit (1);
	}
	SSLeay_add_ssl_algorithms(); //initialize the supported algorithms

	ctx = SSL_CTX_new(TLSv1_2_client_method()); // create a secure context
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        printf("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        printf("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        printf("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, secretkey, SSL_FILETYPE_PEM) != 1)
        printf("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        printf("Error setting cipher list (no valid ciphers)");
	

	ssl = SSL_new(ctx); // create a free and secure connetion
	SSL_set_fd(ssl,sd); // assign a file descriptor
	if (connect(sd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
		perror("connect error");
		exit (1);
	}
	



	if (SSL_connect(ssl)<0){
		fprintf(stderr,"Errore in SSL_connect\n");
		exit(1);
	}
	server_cert = SSL_get_peer_certificate(ssl);
	    if (server_cert != NULL) 
	    {
 
		    printf ("Server certificate:\n");     
		    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		    
		    printf ("\t subject: %s\n", str);
		    
		    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		    
		    printf ("\t issuer: %s\n", str);
		    
		    X509_free(server_cert);
	    } 
 
	    else
 
		    printf("The SSL Server does not have certificate.\n");
	
	// do a secure and private connect
	//SSL_write(ssl,buff_out, strlen(buff_out)); // do a secure write
	//SSL_read(ssl, buff_in, LEN); // do a secure read
	//printf("Ho ricevuto:\n \t%s \n",buff_in);
	char  data[65];
	while (SSL_read(ssl, data, 65)>0) {
		
		fprintf(fp1,"%s",data);

	}	
	SSL_shutdown(ssl); // close a secure connection
	SSL_free(ssl); // free memory
	SSL_CTX_free(ctx); // free memory
}