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

int main(int argc,char *argv[]){
    if (argc < 3) {
        printf("usage %s <host_ip> <port>\n",argv[0]);
        exit(1);
    }

    int port_no = atoi(argv[2]);

    const SSL_METHOD *my_ssl_method;
    SSL_CTX *my_ssl_ctx;
    SSL *my_ssl;
    int my_fd;
    struct sockaddr_in server;
    int error = 0;
    char buffer[512];
    char read_message[512];

    memset(buffer,'\0',sizeof(buffer));
    memset(read_message,'\0',sizeof(read_message));

    printf("Enter a messsage to send the server\n");
    //scanf("%s",buffer);
    fgets(buffer,sizeof(buffer),stdin);

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    my_ssl_method = TLS_client_method();

    if((my_ssl_ctx = SSL_CTX_new(my_ssl_method)) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    if((my_ssl = SSL_new(my_ssl_ctx)) == NULL) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }

    my_fd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port_no);

    inet_aton(argv[1],&server.sin_addr);
    bind(my_fd, (struct sockaddr *)&server, sizeof(server));
    connect(my_fd,(struct sockaddr *)&server, sizeof(server));
    SSL_set_fd(my_ssl,my_fd);

    if(SSL_connect(my_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    printf("[%s,%s]\n",SSL_get_version(my_ssl),SSL_get_cipher(my_ssl));

    error = SSL_write(my_ssl, buffer, strlen(buffer));
    if(error <= 0)
        printf("Write error\n");

    error = SSL_read(my_ssl,read_message,sizeof(read_message));
    if(error <= 0){
        printf("Read error\n");
    }
    else{
        printf("%s\n",read_message);
    }
    

    SSL_shutdown(my_ssl);
    SSL_free(my_ssl);
    SSL_CTX_free(my_ssl_ctx);
    close(my_fd);
    

}