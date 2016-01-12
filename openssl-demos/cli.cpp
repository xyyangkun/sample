/* cli.cpp  -  Minimal ssleay client for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with SSLeay-0.9.0b and OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { printf("error:%d\n", err);ERR_print_errors_fp(stderr); exit(2); }

//定义服务器属性
#define SERVERIP "172.20.1.209"
#define SERVERPORT 8001

//把数字转换成字符串
#define _STR(s) #s

//打印调试
#define DEBUG
#ifdef DEBUG
#define printd(arg, ...) fprintf(stdout,"%s %d:" arg, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define printd(arg, ...)
#endif

//定义是否需要http认证，就是输入密码的意思
#define AUTH
//认证的用户名和密码
#ifdef AUTH
	#define USER "u"
	#define PASSWD "2"
#endif

int main ()
{
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    server_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;

  SSLeay_add_ssl_algorithms();
#ifndef OPENSSL_NO_SSL2
  meth = (SSL_METHOD*)SSLv2_client_method();
#else
  ///meth = (SSL_METHOD*)SSLv3_client_method();
  //连接https 需要使用tls类型的
  meth = (SSL_METHOD*)TLSv1_2_client_method();
  //return ThrowException(Exception::Error(String::New("SSLv2 methods disabled")));
#endif
  SSL_load_error_strings();
  ctx = SSL_CTX_new (meth);
  if(ctx==NULL)
  {
	  printd("ctx is NULL\n");
	  exit(1);
  }

  CHK_SSL(err);
  
  /* ----------------------------------------------- */
  /* Create a socket and connect to server using normal socket calls. */
  
  sd = socket (AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
 
  memset (&sa, '\0', sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = inet_addr (SERVERIP);   /* Server IP */
  sa.sin_port        = htons     (SERVERPORT);          /* Server Port number */
  
  err = connect(sd, (struct sockaddr*) &sa,
		sizeof(sa));                   CHK_ERR(err, "connect");

  /* ----------------------------------------------- */
  /* Now we have TCP conncetion. Start SSL negotiation. */
  printd("connect to %s:%d success.\n",SERVERIP, SERVERPORT);
  
  ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
  printd("SSL_new ok\n");
  SSL_set_fd (ssl, sd);
  printd("Set fd OK\n");
  err = SSL_connect (ssl);                     CHK_SSL(err);
    
  /* Following two steps are optional and not required for
     data exchange to be successful. */
  
  /* Get the cipher - opt */

  printd ("SSL connection using %s\n", SSL_get_cipher (ssl));
  //验证证书是否可以信任
  if ( X509_V_OK != SSL_get_verify_result(ssl) )
  {
	  printd("SSL verify error\n");

	     int color = 32;

		       printf("\033[%dmHello, world.\n\033[0m", color);
  }

  
  /* Get server's certificate (note: beware of dynamic allocation) - opt */
  //比如连接 https时，需要打开以下选项
#if 1
  server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);
  printd ("Server certificate:\n");
  
  str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
  CHK_NULL(str);
  printd ("\t subject: %s\n", str);
  OPENSSL_free (str);

  str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
  CHK_NULL(str);
  printd ("\t issuer: %s\n", str);
  OPENSSL_free (str);

  /* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */

  X509_free (server_cert);
  
#endif
  /* --------------------------------------------------- */
  /* DATA EXCHANGE - Send a message and receive a reply. */


#ifdef AUTH
  //init base 64
  //come from : http://doctrina.org/Base64-With-OpenSSL-C-API.html
  BIO *bio, *b64;
  char* base64EncodeOutput;
  BUF_MEM *bufferPtr;
  char message[] = USER ":" PASSWD;
  unsigned int message_len = strlen(message);
  //printf("base encode str:->%s<-  message len:%d\n", message, message_len);

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  /*
  ///!IMPORTANT
  //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  //BIO_FLAGS_BASE64_NO_NL: 编码结果中，每64个字符换行一次，整个编码后的字符串的末尾也有换行
  //如果有这个选项,测试结尾会出现0x76 0x7f字符 0x7f是del所以打印时显示正常，其实不正常
  */
  BIO_write(bio, message, strlen(message));
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  char b64text[1024]={0};
  strcpy(b64text, (*bufferPtr).data);
  memcpy(b64text, (*bufferPtr).data, bufferPtr->length);
  printd("base64 encode str: ->%s<-, size:%ld\n", b64text, strlen(b64text));
  //printd("%x %x %x %x %x %x\n", b64text[0],b64text[1],b64text[2],b64text[3],b64text[4],b64text[5]);

 
#endif

  /*
   * 以下是模拟浏览器登陆https://172.20.1.209:8001的过程
   *
   * 服务器是python做的，服务器代码从：
   *  https://github.com/SevenW/httpwebsockethandler.git
   *  下载，
   *  运行服务器的命令：
   *  python ExampleWSServer.py 8001 secure u:2
   */
  char http_get_str[2048] = {0};
  sprintf(http_get_str,
	  "GET / HTTP/1.1\r\n"
	  "Host: %s:%d \r\n"
#ifdef AUTH
	  "Authorization: Basic %s\r\n"
#endif
	  "Connection: keep-alive\r\n"
	  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/* ;q=0.8\r\n"
	  "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.86 Safari/537.36\r\n"
	  "Accept-Encoding: gzip, deflate, sdch\r\n"
	  "Accept-Language: en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4,zh-TW;q=0.2\r\n"
	  "\r\n"
	,SERVERIP, SERVERPORT 
#ifdef AUTH
	,b64text
#endif
	);

  printd("http get str: ->%s<- len:%ld\n", http_get_str, strlen(http_get_str));

  err = SSL_write (ssl, http_get_str, strlen(http_get_str));  CHK_SSL(err);
  
  err = SSL_read (ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
  buf[err] = '\0';
  printd ("Got %d chars:'%s'\n", err, buf);
  SSL_shutdown (ssl);  /* send SSL/TLS close_notify */

  /* Clean up. */

  close (sd);
  SSL_free (ssl);
  SSL_CTX_free (ctx);
}
/* EOF - cli.cpp */
