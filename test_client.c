#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "user_config.h"


void print_certificate_details(SSL_CTX* ctx);
static int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

int main ()
{              
    unsigned int message_count = 0;
    unsigned int len = 0;
    int reuse = 1;
    int ret = 0;
    SOCKET sockfd = -1;
    struct sockaddr_in dest = {0};
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char send_buf[MAXBUF] = {0};
    char recv_buf[MAXBUF] = {0};
    const SSL_METHOD *meth = NULL;

    /* SSL 库初始化 */
    SSL_library_init();
    printf("1. SSL lib init!\n");

    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    printf("2. SSL load all algorithms!\n");

    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    printf("3. SSL load all error strings\n");

    do {
        /* 选择客户端方法 */
        meth = TLS_client_method();
        if (NULL == meth) {
            printf("4. Select client method failed!\n");
            break;
        }
        printf("4. Select client method!\n");

        /* 创建SSL_CTX对象 */
        ctx = SSL_CTX_new(meth);
        if (ctx == NULL) {
            printf("5. Create SSL_CTX object failed!\n");
            break;
        }
        printf("5. Create SSL_CTX object success!\n");

        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

#if(SSL_ONE_WAY_AUTH == 1)
        /* 单向认证 */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
        printf("6. Use one-way authentication!\n");
#else
        /* 双向认证 */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
        printf("6. Use two-way authentication!\n");
#endif
        
        /* 若需要验证对方,则载入ca证书(未安装 */
        if (SSL_CTX_load_verify_locations(ctx, NULL, CA_CERT_PATH) <= 0) {
            printf("7. SSL_CTX_load_verify_locations error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        printf("7. Load ca root cert success!\n");
#if(SSL_ONE_WAY_AUTH == 2)
        /* 载入用户的数字证书,此证书用来发送给客户端,证书里包含有公钥 */
        if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_PATH, SSL_FILETYPE_PEM) <= 0) {
            printf("8. Load user cert failed! path = %s\n", CLIENT_CERT_PATH);
            break;
        } else {
            /* 输出客户端证书信息 */
            print_certificate_details(ctx);
        }
        printf("8. Load user cert success!\n");

        /* 载入用户私钥,以用于签名 */
        if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
            printf("9. Load user private key failed! path = %s\n", CLIENT_KEY);
            break;
        }
        printf("9. Load user private key success!\n");

        /* 检查用户私钥是否正确 */
        if (!SSL_CTX_check_private_key(ctx)) {
            printf("10. Private key does not match the certificate public key!\n");
            break;
        }
        printf("10. Private key matches the certificate public key!\n");
#endif
        /* 设置支持的加密方式 */
        if (SSL_CTX_set_cipher_list(ctx, SECURE_CIPHER_LIST) != 1) {
            printf("11. SSL_CTX_set_cipher_list error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }

        /* 创建套接字 */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            printf("12. Create socket fail\n");
            break;
        }
        printf("12. Create a socket[%d]\n", sockfd);
 
        /* 初始化套接字地址结构 */
        bzero(&dest, sizeof(dest));
        dest.sin_family         = AF_INET;
        dest.sin_addr.s_addr    = inet_addr(SERVER_ADDR);
        dest.sin_port           = htons(SERVER_PORT);
        printf("13. Init socket address success!\n");

        /* 连接服务端 */
        errno = 0;
        ret = connect(sockfd, (struct sockaddr *) &dest, sizeof(dest));
        if (ret != 0) {
            printf("14. Client connect failed! ret: %d, error info: %s\n", ret, strerror(errno));
            break;
        }
        printf("14. Client connect to [%s:%d] success!\n", SERVER_ADDR, SERVER_PORT);

        /*创建ssl句柄 */
        ssl = SSL_new(ctx);
        if (ssl == NULL) {
            printf("15. SSL_new failed!\n");
            break;
        }
        printf("15. SSL_new success!\n");

        /* 设置套接字到ssl句柄 */
        ret = SSL_set_fd(ssl, sockfd);
        if (ret == 0) {
            /* 设置失败 */
            printf("16. SSL_set_fd failed! info: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        printf("16. SSL_set_fd success!\n");

        /* 设置SSL连接状态 */
        SSL_set_connect_state(ssl);
        printf("17. SSL_set_connect_state success!\n");

        /* SSL 握手 */
        ret = SSL_do_handshake(ssl);
        if (ret != 1) {
            printf("18. Client SSL_do_handshake fail! info: %s\n", ERR_error_string(ERR_get_error(), NULL));
            break;
        }
        printf("18. Client SSL_do_handshake success!\n");

        /* 开始SSL通信 */
        printf("19. Begin SSL data exchange:\n");
        while(1){
            memset(send_buf, 0, MAXBUF);
            memset(recv_buf, 0, MAXBUF);
            /* send */
            sprintf(send_buf, "client_%d", message_count++);
            len = SSL_write(ssl, send_buf, strlen(send_buf));
            if(len > 0){
                printf(" Send message: %s\n", send_buf);
            } else {
                printf(" Send error!\n");
                break;
            }
            /* recv */
            len = SSL_read(ssl, recv_buf, MAXBUF);
            if(len > 0){
                printf(" Recv message: %s\n", recv_buf);
            }else {
                printf(" Recv error!\n");
                break;
            }
            sleep(1);
        }

        printf(" Client session[%d] is end!\n", sockfd);
    } while (0);


    printf("20. Client session end!\n");
    /* 释放资源 */
    if(ssl != NULL){
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if(sockfd >= 0){
        close(sockfd);
    }
    if(ctx != NULL){
        SSL_CTX_free(ctx);
    }
    return 0;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    char not_before_str[256] = {0};
    char not_after_str[256] = {0};
    char subject_str[256] = {0};
    char issuer_str[256] = {0};
    ASN1_TIME* not_before = NULL;
    ASN1_TIME* not_after = NULL;
    BIO* bio = NULL;
    int error_code = 0;
    int depth = 0;
    X509* cert = NULL;
    X509_NAME* subject_name = NULL;
    X509_NAME* issuer_name = NULL;

    do
    {
        /* obtain the certificate being verified */
        cert = X509_STORE_CTX_get_current_cert(ctx);
        if(cert == NULL){
            break;
        }

        /* determine if the certificate is valid */
        error_code = X509_STORE_CTX_get_error(ctx);
        if (error_code != X509_V_OK) {
            printf("cert invalid, error_info: %s\n", X509_verify_cert_error_string(error_code));
            break;
        }

        /* get cert depth */
        // depth = X509_STORE_CTX_get_error_depth(ctx);
        
        /* create bio object */
        bio = BIO_new(BIO_s_mem());
        if(bio == NULL){
            break;
        }

        /* get validity period */
        (void)ASN1_TIME_print(bio, X509_get_notBefore(cert));
        BIO_gets(bio, not_before_str, sizeof(not_before_str));
        BIO_reset(bio);
        (void)ASN1_TIME_print(bio, X509_get_notAfter(cert));
        BIO_gets(bio, not_after_str, sizeof(not_after_str));
        BIO_free(bio);

        /* get subject name */
        subject_name = X509_get_subject_name(cert);
        X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));

        /* get issuer name */
        issuer_name = X509_get_issuer_name(cert);
        X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));

        if(!X509_NAME_cmp(subject_name, issuer_name)){
            printf("-------------------Root certificate information--------------------\n");
            printf("Subject     : %s\n", subject_str);
            printf("Issuer      : %s\n", issuer_str);
            printf("Before      : %s\n", not_before_str);
            printf("After       : %s\n", not_after_str);
            printf("-------------------------------------------------------------------\n");            
        } else {
            printf("-------------------Peer certificate information--------------------\n");
            printf("Subject     : %s\n", subject_str);
            printf("Issuer      : %s\n", issuer_str);
            printf("Before      : %s\n", not_before_str);
            printf("After       : %s\n", not_after_str);
            printf("-------------------------------------------------------------------\n"); 
        }
    } while (0);
    
    return preverify_ok;
}

void print_certificate_details(SSL_CTX* ctx) 
{
    X509* cert = SSL_CTX_get0_certificate(ctx);
    BIO* bio = NULL;
    char not_before_str[256] = {0};
    char not_after_str[256] = {0};
    char subject_str[256] = {0};
    char issuer_str[256] = {0};
    X509_NAME* subject_name = NULL;
    X509_NAME* issuer_name = NULL;

    bio = BIO_new(BIO_s_mem());

    /* get validity period */
    (void)ASN1_TIME_print(bio, X509_get_notBefore(cert));
    BIO_gets(bio, not_before_str, sizeof(not_before_str));
    BIO_reset(bio);
    (void)ASN1_TIME_print(bio, X509_get_notAfter(cert));
    BIO_gets(bio, not_after_str, sizeof(not_after_str));
    BIO_free(bio);
    
    /* get subject name */
    subject_name = X509_get_subject_name(cert);
    X509_NAME_oneline(subject_name, subject_str, sizeof(subject_str));

    /* get issuer name */
    issuer_name = X509_get_issuer_name(cert);
    X509_NAME_oneline(issuer_name, issuer_str, sizeof(issuer_str));

    printf("------------------Client certificate information-------------------\n");
    printf("Subject     : %s\n", subject_str);
    printf("Issuer      : %s\n", issuer_str);
    printf("Before      : %s\n", not_before_str);
    printf("After       : %s\n", not_after_str);
    printf("-------------------------------------------------------------------\n");
}