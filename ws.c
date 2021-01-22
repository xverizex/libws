#include "ws.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <assert.h>
#include <zlib.h>

static const char *GUID_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const char *sec_websocket_key = "dGhlIHNhbXBsZSBub25jZQ==";
static const char *error_ht = "Not found domain host";
static const char *switch_protocol = "HTTP/1.1 101 Switching Protocols";

struct params {
	char type_ws[255];
	char site_host[512];
	char room[255];
};

static int get_type_ws ( const char *type ) {
	if ( !strncmp ( type, "ws", 3 ) ) return TYPE_WS;
	if ( !strncmp ( type, "wss", 4 ) ) return TYPE_WSS;
	return WS_ERROR_UNKNOWN_TYPE_WS;
}

static void parse_error ( const int ret, char **error ) {
	switch ( ret ) {
		case WS_ERROR_PARSE_WS_SITE: *error = strdup ( "Not found protocol parse ws or wss" ); break;
		case WS_ERROR_PARSE_WS_HOST: *error = strdup ( "Not found parse host" ); break;
		case WS_ERROR_PARSE_WS_ROOM: *error = strdup ( "Not found parse room" ); break;
		case WS_ERROR_HOST: *error = strdup ( "Not found host" ); break;
		case WS_ERROR_CREATE_SOCKET: *error = strdup ( "Error for create socket" ); break;
		case WS_ERROR_UNKNOWN_TYPE_WS: *error = strdup ( "Unknown type. select between ws and wss" ); break;
		case WS_ERROR_CANT_CONNECT_TO_HOST: *error = strdup ( "Can't connect to host" ); break;
		case WS_ERROR_HANDSHAKE: *error = strdup ( "Error handshake" ); break;
	}
}

static int handshake ( struct params *pr, const char *ip_origin, const int type, const int fd, SSL *ssl ) {
	char buf[4096];
	snprintf ( buf, 4096,
			"GET /%s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Origin: %s\r\n"
			"Sec-WebSocket-Protocol: chat, superchat\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n"
			,
			pr->room,
			pr->site_host,
			sec_websocket_key,
			ip_origin
		 );

	int ret;

	switch ( type ) {
		case TYPE_WS:
			write ( fd, buf, strlen ( buf ) );
			ret = read ( fd, buf, 4096 );
			buf[ret] = 0;
			if ( strncmp ( buf, switch_protocol, strlen ( switch_protocol ) ) ) return WS_ERROR_HANDSHAKE;
			break;
		case TYPE_WSS:
			assert ( ssl != NULL );
			SSL_write ( ssl, buf, strlen ( buf ) );
			ret = SSL_read ( ssl, buf, 4096 );
			buf[ret] = 0;
			if ( strncmp ( buf, switch_protocol, strlen ( switch_protocol ) ) ) return WS_ERROR_HANDSHAKE;
			break;
	}

	return WS_OK;
}

static int parse_site ( const char *site, struct params *pr ) {
	/* ws or wss ? */
	const char *s = site;
	for ( int i = 0; i < 255; i++ ) {
		if ( *s == 0 ) return WS_ERROR_PARSE_WS_SITE;
		if ( *s == ':' && i == 0 ) return WS_ERROR_PARSE_WS_SITE;
		if ( *s == ':' ) {
			pr->type_ws[i] = 0;
			s += 3;
			break;
		}
		pr->type_ws[i] = *s;
		s++;
	}

	/* host */
	for ( int i = 0; i < 512; i++ ) {
		if ( *s == 0 ) return WS_ERROR_PARSE_WS_HOST;
		if ( *s == '/' && i == 0 ) return WS_ERROR_PARSE_WS_HOST;
		if ( *s == '/' ) {
			pr->site_host[i] = 0;
			break;
		}
		pr->site_host[i] = *s;
		s++;
	}

	/* room */
	for ( int i = 0; i < 255; i++ ) {
		if ( *s == 0 && i == 1 ) return WS_ERROR_PARSE_WS_ROOM;
		if ( *s == 0 ) {
			pr->room[i] = 0;
			break;
		}
		pr->room[i] = *s;
		s++;
	}

	return WS_OK;
}

struct ws *ws_init ( const char *site, const unsigned short port, char **error ) {
	assert ( *error == NULL );

	struct params params;
	int ret;

	ret = parse_site ( site, &params );
	if ( ret < 0 ) {
		parse_error ( ret, error );
		return NULL;
	}

	struct hostent *ht = gethostbyname ( params.site_host );
	if ( !ht ) {
		ret = WS_ERROR_HOST;
		parse_error ( ret, error );
		return NULL;
	}

	struct sockaddr_in s;
	s.sin_family = AF_INET;
	s.sin_port = htons ( port );
	s.sin_addr.s_addr = *( ( in_addr_t * ) ht->h_addr );
	int fd = socket ( AF_INET, SOCK_STREAM, 0 );
	if ( fd == -1 ) {
		ret = WS_ERROR_CREATE_SOCKET;
		parse_error ( ret, error );
		return NULL;
	}

	int type = get_type_ws ( params.type_ws );
	if ( type < 0 ) {
		parse_error ( type, error );
		return NULL;
	}

	char ip_origin[512 + 16 + 7 + 1];
	switch ( type ) {
		case TYPE_WS: snprintf ( ip_origin, 512 + 16, "http://127.0.0.1" ); break;
		case TYPE_WSS: snprintf ( ip_origin, 512 + 16, "https://127.0.0.1" ); break;
	}

	ret = connect ( fd, ( const struct sockaddr * ) &s, sizeof ( s ) );
	if ( ret == -1 ) {
		ret = WS_ERROR_CANT_CONNECT_TO_HOST;
		parse_error ( ret, error );
		return NULL;
	}

	SSL *ssl = NULL;
	SSL_CTX *ctx = NULL;

	switch ( type ) {
		case TYPE_WS:
			ret = handshake ( &params, ip_origin, type, fd, NULL );
			if ( ret < 0 ) {
				close ( fd );
				parse_error ( ret, error );
				return NULL;
			}
			break;
		case TYPE_WSS: {
				       ctx = SSL_CTX_new ( SSLv23_client_method ( ) );
				       ssl = SSL_new ( ctx );
				       SSL_set_fd ( ssl, fd );
				       SSL_connect ( ssl );
				       ret = handshake ( &params, ip_origin, type, -1, ssl );
				       if ( ret < 0 ) {
					       SSL_CTX_free ( ctx );
					       SSL_free ( ssl );
					       close ( fd );
					       parse_error ( ret, error );
					       return NULL;
				       }
				       break;
			       }
	}

	struct ws *ws = calloc ( 1, sizeof ( struct ws ) );
	ws->ssl = ssl;
	ws->ctx = ctx;
	ws->fd = fd;
	ws->type = type;

	return ws;
}

static void set_mask_pre ( unsigned char *message, const char *data, const int length ) {
	unsigned char *s = &message[2];
	unsigned char *ss = s;
	for ( int i = 0; i < 4 && i < length; i++ ) {
		s[i] = data[i] ^ data[i % 4];
	}
	s += 4;
	for ( int i = 0; i < length; i++ ) {
		s[i] = data[i] ^ ss[i % 4];
	}
}

static void set_mask_post ( unsigned char *message, const char *data, const int length ) {
	unsigned short len = length;
	message[2] = len >> 8 & 0xff;
	message[3] = len >> 0 & 0xff;
	unsigned char *s = &message[4];
	unsigned char *ss = s;
	for ( int i = 0; i < 4; i++ ) {
		ss[i] = data[i] ^ data[i % 4];
	}
	s += 4;
	for ( int i = 0; i < length; i++ ) {
		s[i] = data[i] ^ ss[i % 4];
	}
}

size_t ws_write ( struct ws *ws, const char *buffer, size_t length ) {
	unsigned char first_byte = 1 << 7;
	first_byte |= 1;
	int total_length = 2 + length + 4;

	unsigned char sb = 1 << 7;

	unsigned char *message = calloc ( total_length, 1 );
	if ( !message ) return -1;

	message[0] = first_byte;

	if ( length < 126 ) {
		sb |= length;
		message[1] = sb;
		set_mask_pre ( message, buffer, length );
	} else if ( length == 126 ) {
		sb |= 126;
		message[1] = sb;
		set_mask_post ( message, buffer, length );
		total_length += 2;
	}

	size_t ret;
	switch ( ws->type ) {
		case TYPE_WS:
			ret = write ( ws->fd, message, total_length );
			free ( message );
			return ret;
		case TYPE_WSS:
			ret = SSL_write ( ws->ssl, message, total_length );
			free ( message );
			return ret;
		default:
			return WS_ERROR_UNKNOWN_TYPE_WS;
	}
}

size_t ws_read ( struct ws *ws, unsigned char *buffer, unsigned int length ) {
	unsigned char *mdt = buffer;
	unsigned char *dt = mdt;
	int total_size = 0;
	int ret = -1;
	unsigned char pong[2] = { 0x8a, 0x00 };

	switch ( ws->type ) {
		case TYPE_WS:
			while ( ( ret = read ( ws->fd, mdt, length ) ) == 16384 ) {
				mdt += ret;
				length -= ret;
				total_size += ret;
			}
			if ( total_size == 0 ) total_size = ret;
			break;
		case TYPE_WSS:
			while ( ( ret = SSL_read ( ws->ssl, mdt, length ) ) == 4096 ) {
				mdt += ret;
				length -= ret;
				total_size += ret;
			}
			if ( total_size == 0 ) total_size = ret;
	}

	if ( ret <= 0 ) return -1;

	if ( dt[0] == 0x89 ) {
		switch ( ws->type ) {
			case TYPE_WS:
				ret = write ( ws->fd, pong, 2 );
				if ( ret == -1 ) return -1;
				break;
			case TYPE_WSS:
				ret = SSL_write ( ws->ssl, pong, 2 );
				if ( ret <= 0 ) return -1;
				break;
		}
	}

	if ( dt[0] == 0x82 ) {
		if ( dt[1] == 0x7e ) {
			int size = ( ( dt[2] & 0x07 ) << 8 ) | dt[3];
			unsigned char *s = &dt[4];
			memcpy ( buffer, s, size );
			return size;
		}
		if ( dt[1] < 0x7e ) {
			int size = ( dt[1] & 0x7f );
			unsigned char *s = &dt[2];
			memcpy ( buffer, s, size );
			return size;
		}
	}

	if ( dt[0] == 0x88 ) {
		if ( dt[1] == 126 ) {
			int size = ( dt[2] << 8 ) | dt[3];
			unsigned char *s = &dt[3];
			memcpy ( buffer, s, size );
			return size;
		}
		if ( dt[1] < 126 ) {
			int size = dt[1];
			unsigned char *s = &dt[2];
			memcpy ( buffer, s, size );
			return size;
		}
	}

	if ( dt[0] == 0x81 ) {
		if ( dt[1] == 126 ) {
			int size = ( dt[2] << 8 ) | dt[3];
			unsigned char *s = &dt[3];
			memcpy ( buffer, s, size );
			return size;
		}
		if ( dt[1] < 126 ) {
			int size = dt[1];
			unsigned char *s = &dt[2];
			memcpy ( buffer, s, size );
			return size;
		}
	}

	return ret;
}

void ws_close ( struct ws *ws ) {
	SSL_CTX_free ( ws->ctx );
	SSL_free ( ws->ssl );
	close ( ws->fd );
}

int ws_gzip_decompress ( unsigned char *in, size_t length_in, unsigned char *out, size_t length_out ) {
	z_stream stmt;
	const size_t total_size = length_out;

	stmt.zalloc = Z_NULL;
	stmt.zfree = Z_NULL;
	stmt.opaque = Z_NULL;
	stmt.avail_in = length_in;
	stmt.next_in = in;
	stmt.avail_out = length_out;
	stmt.next_out = out;

	int ret = inflateInit2 ( &stmt, 15 + 16 );
	if ( ret != Z_OK ) return WS_ERROR;
	
	ret = inflate ( &stmt, Z_NO_FLUSH );
	if ( ret == Z_STREAM_END ) {
		inflateEnd ( &stmt );
		length_out = total_size - stmt.avail_out;
		out[length_out] = 0;
		return WS_OK;
	}
	inflateEnd ( &stmt );
	length_out = total_size - stmt.avail_out;
	out[length_out] = 0;

	return WS_ERROR;
}
