
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#include <stdlib.h>
#include <string.h>

#define SERVER_NAME "google.com"
#define SERVER_PORT "443"

static void my_debug(void *ctx, int level, const char *file, int line, const char *str){
    ((void) level);
    fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush( (FILE *) ctx);
}

int main(){
    int returncode;
    const char *sendcmd = "GET / HTTP/1.1\r\n\r\n";
    const char *pers = "client"; //used for the entropy seed. Should get it from someplace that makes sense
    char *response;

    /* init setup args */
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    

    returncode = mbedtls_ctr_drbg_seed(&ctr_drbg, 
            mbedtls_entropy_func, 
            &entropy, (const unsigned char *) pers, 
            strlen(pers));
    if(returncode != 0){
        printf("failed\n | mbedtls_ctr_drbg_seed returned %d\n", returncode);
        goto exit;
    }

    returncode = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    if( returncode  != 0){
        printf("Failed\n ! mbedtls_net_connect returned %d\n\n", returncode);
        goto exit;
    }

    returncode = mbedtls_ssl_config_defaults(&conf, 
            MBEDTLS_SSL_IS_CLIENT, 
            MBEDTLS_SSL_TRANSPORT_STREAM, 
            MBEDTLS_SSL_PRESET_DEFAULT);

    if(returncode != 0){
        printf("failed\n ! mbedtls_ssl_config_defaults returned %d\n\n", returncode);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); //dis is bad mukay

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    returncode = mbedtls_ssl_setup(&ssl, &conf);
    if(returncode !=0){
        printf("Failed\n ! mbedtls_ssl_setup returned %d\n\n", returncode);
        goto exit;
    }

    returncode = mbedtls_ssl_set_hostname(&ssl, "google.com");
    if(returncode != 0){
        printf("Failed\n ~ mbedtls_ssl_set_hostname return %d\n\n", returncode);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while((returncode = mbedtls_ssl_handshake(&ssl)) !=0){
        if(returncode != MBEDTLS_ERR_SSL_WANT_READ && returncode != MBEDTLS_ERR_SSL_WANT_WRITE){
            printf("failed\n ! mbedtls_ssl_handshake returned -0x%x\n\n", -returncode);
            goto exit;
        }
    }

    while((returncode = mbedtls_ssl_write(&ssl, (const unsigned char*)sendcmd, strlen(sendcmd))) <= 0){
        if(returncode != 0){
            printf("Failed\n ! write returned %d\n\n", returncode);
            printf("Size: %ld\n", strlen(sendcmd));
            goto exit;
        }
    }
    printf("%d bytes written\n\n%s", returncode, sendcmd);
    int len = 4096;
    response = (char*)malloc(len * sizeof(char));
    do{
        memset(response, 0, len);
        returncode = mbedtls_ssl_read(&ssl, (unsigned char*) response, len);
        
        if(returncode <= 0){
            printf("failed\n ! ssl_read returned %d\n\n", returncode);
            break;
        }
        printf("%d bytes read\n", returncode);

    }while(1);
    free(response);

exit:
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&cacert);

    return returncode;

}

