#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"
#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_clnt(void *arg);
void send_msg(char *msg, int len, SSL *ssl);
void error_handling(char *msg);

int clnt_cnt = 0;
SSL *clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;
SSL_CTX *ssl_ctx;


int main(int argc, char *argv[])
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        perror("Unable to load certificate/key");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;
    pthread_t t_id;
    if (argc != 2) {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    pthread_mutex_init(&mutx, NULL);
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");

    while (1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);

        if (SSL_accept(ssl) <= 0) {
            perror("TLS handshake failed");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = ssl;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)ssl);
        pthread_detach(t_id);
        printf("Connected client IP: %s\n", inet_ntoa(clnt_adr.sin_addr));
    }

    close(serv_sock);
    SSL_CTX_free(ssl_ctx);
    return 0;
}

void *handle_clnt(void *arg)
{
    SSL *ssl = (SSL*)arg;
    int str_len = 0, i;
    char msg[BUF_SIZE];

    while ((str_len = SSL_read(ssl, msg, sizeof(msg))) > 0)
        send_msg(msg, str_len, ssl);

    pthread_mutex_lock(&mutx);
    for (i = 0; i < clnt_cnt; i++) {
        if (ssl == clnt_socks[i]) {
            while (i < clnt_cnt - 1) {
                clnt_socks[i] = clnt_socks[i + 1];
                i++;
            }
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    return NULL;
}

void send_msg(char* msg, int len, SSL* ssl) 
{
    int i;
    pthread_mutex_lock(&mutx);
    for (i = 0; i < clnt_cnt; i++)
        SSL_write(clnt_socks[i], msg, len);
    pthread_mutex_unlock(&mutx);
}

void error_handling(char* msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}
