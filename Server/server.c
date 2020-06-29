#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <string.h>



#define PORT 3000
#define CIPHER_LIST "ECDHE-RSA-AES256-GCM-SHA384"
#define CAFILE "Cert/cacert.pem"
#define CADIR NULL
#define CERTFILE "Cert/servercert.pem"
#define KEYFILE "Cert/serverkey.pem"

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
	X509 * client_cert;
	int sd, connsd, cnt, lencliaddr;
	struct sockaddr_in servaddr, clientaddr;
	char * str;
	FILE* fp1;

	



	//opening a connection TCP/IP
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
	
 	//set as secure server only the ones certificated from the CA certification saved in CAFILE
    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        printf("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        printf("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        printf("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
        printf("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER,
                       verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 |
                             SSL_OP_SINGLE_DH_USE);
    //set the valid cipher list
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
		
		//check for the server certificate
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

		    
		    

		    
		    



   			//only if the cliet is a Medical Center
		    if(strncmp(ret,"/CN=Asl Campania Medical Center",31)==0){
		    	printf("Loading skt from Medical Center\n");

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
				printf("No good certificate to load a skt\n");
			}

	    } 
 
	    else{
	    	//if no cert is provided is a normal user waiting for the skt list 
	    	printf("The SSL client does not have certificate.\n");
	    	printf("Sending skt list to user\n");
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
	SSL_CTX_free(ctx);
}
