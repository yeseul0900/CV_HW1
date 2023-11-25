# CV_HW1

compiler version  : gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
Ubuntu version : 22.04
OpenSSL version  : 3.1.4


1. 인증서 만들기
   a. server.key 만들기
   openssl genpkey -algorithm RSA -out server.key
   b. 인증서 정보 생성하기
   openssl req -new -key server.key -out server.csr
   c. server.crt 만들기
   openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
2. 터미널에서 make로 컴파일러 실행(각 3개의 터미널 필요)
3. ./chat_serv <port 번호>
4. ./chat_clnt <IP주소> <port 번호> <이름> 두번 실행
5. 채팅하기

   
