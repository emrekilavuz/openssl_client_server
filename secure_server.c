#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// EMRE KILAVUZ
// 220201019

int main(int argc,char* argv[]){

    if(argc<2){
        printf("usage error, missing <port> argument\n");
        exit(1);
    }

    int my_fd,client_fd;
    struct sockaddr_in server, client;
    int client_size;
    int error = 0;
    const SSL_METHOD *my_ssl_method;
    SSL_CTX *my_ssl_ctx;
    SSL *my_ssl;
    char read_message[512];

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    my_ssl_method = TLS_server_method();

    if( ( my_ssl_ctx = SSL_CTX_new(my_ssl_method) ) == NULL ) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    SSL_CTX_use_certificate_file(my_ssl_ctx, "server.pem", SSL_FILETYPE_PEM); 
    SSL_CTX_use_PrivateKey_file(my_ssl_ctx, "server.pem", SSL_FILETYPE_PEM);

    if( !SSL_CTX_check_private_key(my_ssl_ctx) ) {    //pe
        fprintf(stderr,"Private key does not match certificate\n");
        exit(-1);
    }

    my_fd = socket(PF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[1]));
    server.sin_addr.s_addr = INADDR_ANY;
    bind(my_fd, (struct sockaddr *)&server, sizeof(server));
    listen(my_fd, 5);

    while(1){
        memset(read_message,'\0',sizeof(read_message));
        client_size = sizeof(client);
        bzero(&client,sizeof(client));
        client_fd = accept(my_fd, (struct sockaddr *)&client, (socklen_t *)&client_size);

        if((my_ssl = SSL_new(my_ssl_ctx)) == NULL) {
            ERR_print_errors_fp(stderr);
            exit(-1);
        }

        SSL_set_fd(my_ssl,client_fd);
        if(SSL_accept(my_ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(-1);
        }

        printf("[%s,%s]\n",SSL_get_version(my_ssl),SSL_get_cipher(my_ssl));

        error = SSL_read(my_ssl,read_message,sizeof(read_message));
        if(error <= 0)
            break;

        printf("%s\n", read_message);

        error = SSL_write(my_ssl, read_message, strlen(read_message));
        if(error <= 0)
            break;

        SSL_shutdown(my_ssl);
        SSL_free(my_ssl);
        close(client_fd);

        if((strcmp(read_message,"quit\n")==0) || (strcmp(read_message,"Quit\n")==0) || (strcmp(read_message,"QUIT\n")==0)){
            break;
        }

    }

    SSL_CTX_free(my_ssl_ctx);



    return 0;
}