#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 100
#define NAME_SIZE 20

void* send_msg(void* arg);
void* recv_msg(void* arg);
void error_handling(char* msg);

SSL_CTX* ssl_ctx;

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

int main(int argc, char* argv[])
{
    SSL_library_init();
    SSL_load_error_strings();
    int sock;
    struct sockaddr_in serv_addr;
    pthread_t snd_thread, rcv_thread;
    void* thread_return;
    if (argc != 4) {
        printf("Usage : %s <IP> <port> <name>\n", argv[0]);
        exit(1);
    }
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    sprintf(name, "[%s]", argv[3]);
    sock = socket(PF_INET, SOCK_STREAM, 0);

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) == -1) {
        perror("TLS handshake failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    pthread_create(&snd_thread, NULL, send_msg, (void*)ssl);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)ssl);
    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);
    close(sock);

    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

void* send_msg(void* arg)   // send thread main
{
    SSL* ssl = (SSL*)arg;
    char name_msg[NAME_SIZE + BUF_SIZE];
    while (1)
    {
        fgets(msg, BUF_SIZE, stdin);
        if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
        {
            SSL_shutdown(ssl);
            exit(0);
        }
        sprintf(name_msg, "%s %s", name, msg);
        SSL_write(ssl, name_msg, strlen(name_msg));
    }
    return NULL;
}

void* recv_msg(void* arg)   // read thread main
{
    SSL* ssl = (SSL*)arg;
    char name_msg[NAME_SIZE + BUF_SIZE];
    int str_len;
    while (1)
    {
        str_len = SSL_read(ssl, name_msg, NAME_SIZE + BUF_SIZE - 1);
        if (str_len == -1)
            return (void*)-1;
        name_msg[str_len] = 0;
        fputs(name_msg, stdout);
    }
    return NULL;
}

void error_handling(char* msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}
