all: chat_serv chat_clnt
chat_serv : tls_chat_serv.c
	gcc -o chat_serv tls_chat_serv.c -lssl -lcrypto -lpthread

chat_clnt : tls_chat_clnt.c
	gcc -o chat_clnt tls_chat_clnt.c -lssl -lcrypto -lpthread	