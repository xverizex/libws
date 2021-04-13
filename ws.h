#ifndef __WS_H
#define __WS_H
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TYPE_WS          1
#define TYPE_WSS         2

struct ws {
	int fd;
	int type;
	SSL *ssl;
	SSL_CTX *ctx;
};

struct ws *ws_init ( const char *site, const unsigned short port, char **error );
size_t ws_write ( struct ws *ws, const char *buffer, size_t length );
size_t ws_read ( struct ws *ws, unsigned char *buffer, unsigned int length );
void ws_close ( struct ws *ws );
int ws_gzip_decompress ( unsigned char *in, size_t length_in, unsigned char *out, size_t length_out );

#define WS_OK                           0
#define WS_ERROR_HOST                  -1
#define WS_ERROR_PARSE_WS_SITE         -2
#define WS_ERROR_PARSE_WS_HOST         -3
#define WS_ERROR_PARSE_WS_ROOM         -4
#define WS_ERROR_CREATE_SOCKET         -5
#define WS_ERROR_UNKNOWN_TYPE_WS       -6
#define WS_ERROR_CANT_CONNECT_TO_HOST  -7
#define WS_ERROR_HANDSHAKE             -8
#define WS_ERROR                       -9

#ifdef __cplusplus
}
#endif

#endif
