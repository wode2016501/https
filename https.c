/*
   gcc https.c -lssl -lcrypto   -o https
   */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BufSize 30 * 1024

int create_socket_listen(int port)
{
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);  if (s < 0) {   perror("Unable to create socket");  exit(EXIT_FAILURE);  }
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {  perror("Unable to bind");  exit(EXIT_FAILURE); }
	if (listen(s, 1) < 0) { perror("Unable to listen"); exit(EXIT_FAILURE);   }

	return s;
}


SSL_CTX* initSSL(const char* cert, const char* key)
{
	//todo 可能存在泄露
	SSL_CTX* ctx;


	/* SSL 库初始化 */
	SSL_library_init();
	/* 载入所有 SSL 算法 */
	OpenSSL_add_all_algorithms();
	/* 载入所有 SSL 错误消息 */
	SSL_load_error_strings();
	/* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text, 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
	ctx = SSL_CTX_new(SSLv23_server_method()); if (ctx == NULL) { ERR_print_errors_fp(stdout);  return NULL; }


	/* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {  ERR_print_errors_fp(stdout);  return NULL;  }
	/* 载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {   ERR_print_errors_fp(stdout);   return NULL;  }
	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(ctx)) {  ERR_print_errors_fp(stdout);  return NULL; }


	return ctx;
}


int main(int argc, char** argv)
{
	printf("运行前请运行:\n\t\topenssl genrsa > privkey.pem\n\t\topenssl req -new -x509 -key privkey.pem > fullchain.pem\n"); 
	int port = 5555;
	int sock;
	SSL_CTX* ctx;
	char buf[BufSize];

	/* Ignore broken pipe signals */
	signal(SIGPIPE, SIG_IGN);

	ctx = initSSL("./fullchain.pem", "./privkey.pem"); if (ctx == NULL) { return 0; }

	sock = create_socket_listen(port);

	/* Handle connections */
	while (1) 
	{
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		SSL* ssl;
		const char reply[] = "HTTP/1.1 200 OK\r\nDate: Fri, 22 May 2009 06:07:21 GMT\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><head></head><body>hello world</body></html>";

		int client = accept(sock, (struct sockaddr*)&addr, &len);  if (client < 0) {  perror("Unable to accept"); exit(EXIT_FAILURE);  }

		ssl = SSL_new(ctx); SSL_set_fd(ssl, client);
		if (SSL_accept(ssl) <= 0) { ERR_print_errors_fp(stderr); goto end; }

		int size = SSL_read(ssl, buf, BufSize); printf("ssl_read(%d): \n%s\n", size, buf); 

		SSL_write(ssl, reply, strlen(reply));

end:
		SSL_shutdown(ssl);  SSL_free(ssl);  close(client);
	}

	close(sock);
	SSL_CTX_free(ctx);
}
