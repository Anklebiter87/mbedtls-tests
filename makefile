

all:
	gcc -o ssl_client  ssl_client.c -I include/ -L lib/ -lmbedtls -lmbedx509 -lmbedcrypto
	gcc -o ssl_server  ssl_server.c -I include/ -L lib/ -lmbedtls -lmbedx509 -lmbedcrypto

clean:
	rm ssl_server
	rm ssl_client
