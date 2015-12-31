all: gateway

gateway:  gateway.c aes256cbc.h aes256cbc.c base64.h base64.c
	gcc -D_GNU_SOURCE -pthread -O3 -o gateway gateway.c aes256cbc.c base64.c -lssl -lcrypto

clean:
	rm gateway