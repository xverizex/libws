# libws

Simple websocket client. There is example how to connect, write and read data from huobi.
```
#include <stdio.h>
#include <string.h>
#include "ws.h"

int main ( int argc, char **argv ) {
	char *error = NULL;
	struct ws *ws = ws_init ( "wss://api.huobi.pro/ws", 443, &error );

	if ( error ) {
		printf ( "%s\n", error );
		exit ( EXIT_FAILURE );
	}

	unsigned char buffer[4096];
	unsigned char out[4096];

	snprintf ( buffer, 4096,
			"{ \"sub\": \"market.btcusdt.kline.1min\","
			"\"id\": \"id1\""
			"}"
		 );

	int ret = ws_write ( ws, buffer, strlen ( buffer ) );

	while ( 1 ) {
		int ret = ws_read ( ws, buffer, 4096 );
		size_t length = 4096;
		ws_gzip_decompress ( buffer, ret, out, length );

		printf ( "%s\n", out );
	}
}
```
