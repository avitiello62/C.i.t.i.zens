#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <string.h>
#define LEN 1024
#define PORT 3000



#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "Cert/cacert.pem"
#define CADIR NULL
#define CERTFILE "Cert/servercert.pem"


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
	char filename[]="Cert/servercert.pem";
	char secretkey[]="Cert/serverkey.pem";
	char buff[LEN];
	char buff_out[]="Ciao client";
	char * str;
	SSL *ssl;
	SSL_CTX *ctx;
	X509 * client_cert;
	char  name[20];
	int sd, connsd, cnt, lencliaddr;
	struct sockaddr_in servaddr, clientaddr;
FILE* fp1;

	




	if ( (sd = socket(AF_INET, SOCK_STREAM, 0)) <0){
		perror("opening socket");
		exit(1);
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);
	if (bind(sd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
		perror("Error in binding");
		exit(1);
	}
	listen(sd, 5);
	SSLeay_add_ssl_algorithms(); // initialize the supported algorithms
	ctx = SSL_CTX_new(TLSv1_2_server_method()); // create a secure context
	// certificate to be used
	
 
    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        printf("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        printf("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        printf("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, secretkey, SSL_FILETYPE_PEM) != 1)
        printf("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 |
                             SSL_OP_SINGLE_DH_USE);
    
    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        printf("Error setting cipher list (no valid ciphers)");

	for ( ; ; ) {
		printf("Waiting for client\n");
		ssl = SSL_new(ctx); // create a free and secure connetionS
		connsd = accept(sd, (struct sockaddr *)&clientaddr, (void *)&lencliaddr);
		SSL_set_fd(ssl,connsd); // assign a file descriptor
		// do a secure accept
		if(SSL_accept(ssl)<0){
			fprintf(stderr,"Errore in SSL Accept \n");
		exit(1);
		}
		
		/* Informational output (optional) */
  	
	    /* Get the client's certificate (optional) */
	    client_cert = SSL_get_peer_certificate(ssl);
	    if (client_cert != NULL) 
	    {
 
		    printf ("Client certificate:\n"); 

			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		    
		    printf ("\t issuer: %s\n", str);   
		    str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		    
		    printf ("\t subject: %s\n", str);
		    
		    char buff[100];
		   	strcpy(buff,str);
   			char *ret;

   			ret = strstr(buff, "/CN");

		    
		    

		    
		    




		    if(strncmp(ret,"/CN=Asl Campania Medical Center",31)==0){
		    	printf("Loading sk0 from Medical Center\n");

			    fp1=fopen("Data/sick_skt.txt","a");
				if (fp1 == NULL){
			    return 1; 
				}
				char data[66];
				SSL_read(ssl,data,66);
				fprintf(fp1,"%s",data);
				X509_free(client_cert);
				SSL_shutdown(ssl); // close a secure connection
				SSL_free(ssl);
				fclose(fp1);
			}else{
				printf("Sending sk0 to user\n");
				fp1=fopen("Data/sick_skt.txt","r");
					if (fp1 == NULL){
			        return 1; 
			    }
				char  data[65];
				while (fgets (data, 65, fp1)!=NULL) {
		    		SSL_write(ssl, data, 65);
		    		
		   		}
				X509_free(client_cert);
				SSL_shutdown(ssl); // close a secure connection
				SSL_free(ssl);
			}

	    } 
 
	    else{

	    	printf("The SSL client does not have certificate.\n");
	    	
			

	    }
 
		    
		
		//cnt = SSL_read(ssl, buff, LEN); // do a secure read
		//buff[cnt] = 0;
		//SSL_write(ssl, buff, cnt+1);
		
	
	}
	SSL_CTX_free(ctx);
}
