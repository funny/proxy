#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "base64.h"
#include "aes256cbc.h"

char *password = "p0S8rX680*48";
char *encrypted = "U2FsdGVkX1+JXKDI/2wFpglXX2zzASqnKhqAiM6GvoI=";

int decrypt(char *buf, int len, char *key, char *iv) {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return 0;
	}
    
	char *plain = malloc(128);

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	int newlen = 0;
	if (1 != EVP_DecryptUpdate(ctx, plain, &newlen, buf, len)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	len = newlen;
	if (1 != EVP_DecryptFinal_ex(ctx, plain + newlen, &newlen)) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_free(ctx);
	
	len += newlen;
	*(plain + len) = '\0';
	printf("%s\n", plain);
	return len;
}

int main(int argc, char *argv[])
{
    unsigned char *plain = malloc(base64_decode_len(encrypted));
    int len = base64_decode(plain, encrypted);

    unsigned char salt[9];
    memcpy(salt, plain + 8, 8);
    salt[8] = 0;
    
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    
    if (!EVP_BytesToKey(cipher, EVP_md5(), plain + 8, password, strlen(password), 1, key, iv)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    int i;
    printf("Len: %d\n", len);
    printf("Header: "); for(i=0; i<8; ++i) { printf("%c", plain[i]); } printf("\n");
    printf("Text: "); for(i=0; i<len; ++i) { printf("%02X", plain[i]); } printf("\n");
    printf("Salt: "); for(i=8; i<16; ++i) { printf("%02X", plain[i]); } printf("\n");
    printf("Key: "); for(i=0; i<cipher->key_len; ++i) { printf("%02X", key[i]); } printf("\n");
    printf("IV: "); for(i=0; i<cipher->iv_len; ++i) { printf("%02X", iv[i]); } printf("\n");
    
    len = decrypt(plain + 16, len - 16, key, iv);
    printf("Text: "); for(i=0; i<len; ++i) { printf("%02X", plain[i]); } printf("\n");
    return 0;
}
