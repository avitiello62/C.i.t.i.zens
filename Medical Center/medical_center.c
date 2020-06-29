#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/ssl.h>



#define PORT 3000

#define CIPHER_LIST "ECDHE-RSA-AES256-GCM-SHA384"
#define CAFILE "Cert/cacert.pem"
#define CADIR NULL
#define CERTFILE "Cert/medicalcentercert.pem"
#define KEYFILE "Cert/medicalcenterkey.pem"

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


int main(int argc, char **argv){
	
	SSL *ssl;
	SSL_CTX *ctx;
	int sd, cnt;
	X509 * server_cert;
	struct sockaddr_in servaddr;
	char * str;

	//opening a file to save all sick skt downloaded from server
	FILE* fp1;
	fp1=fopen("Data/sick_skt.txt","r");
		if (fp1 == NULL){
        return 1; 
    }
	//recquires as second argoument the ip address of the server
	if (argc != 2) {
		fprintf(stderr,"usage: %s <IPaddress>\n", argv[0]);
		exit (1);
	}
	//opening a connection TCP/IP
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
	//set as secure server only the ones certificated from the CA certification saved in CAFILE
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        printf("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        printf("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        printf("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
        printf("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
    //set the valid cipher list
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
	//check for the server certificate
	server_cert = SSL_get_peer_certificate(ssl);
	    if (server_cert != NULL) 
	    {
 
		    printf ("Server certificate:\n"); 

			str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
		    
		    printf ("\t issuer: %s\n", str);   
		    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		    
		    printf ("\t subject: %s\n", str);

		    char buff[100];
		   	strcpy(buff,str);
   			char *ret;

   			ret = strstr(buff, "/CN");

		   //only if the server is a Contact Server 
		    if(strncmp(ret,"/CN=Asl Campania Contact Server",31)==0){
		    	char  data[66];
				fgets(data, 66, fp1);
				SSL_write(ssl,data,66);	
		    } 
		}
 
	    else{
 
		    printf("The SSL Server does not have certificate.\n");
	
	}
	
	SSL_shutdown(ssl); // close a secure connection
	SSL_free(ssl); // free memory
	SSL_CTX_free(ctx); // free memory
	fclose(fp1);
}



