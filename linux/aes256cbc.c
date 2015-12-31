#include <openssl/evp.h>
#include <string.h>
#include "base64.h"

int aes256cbc_decrypt(unsigned char *passphrase, unsigned char *buf) {
	unsigned char key[EVP_MAX_KEY_LENGTH];
	unsigned char iv[EVP_MAX_IV_LENGTH];
	
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
	
	int len = base64_decode(buf, buf);
	if (len < 16 /* AES Block Size */) {
		return 0;
	}
	
	if (!strncmp(buf, "Slated__", 8)) {
		return 0;
	}
	
	if (!EVP_BytesToKey(cipher, EVP_md5(), 
	buf + 8 /* skip "Slated__" */, 
	passphrase, strlen(passphrase), 1, 
	key, iv)) {
		return 0;
	}
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		return 0;
	}
	
	if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	int newlen = 0;
	if (1 != EVP_DecryptUpdate(ctx, buf, &newlen, 
	buf + 16 /* skip slat header */, len - 16)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	len = newlen;
	if (1 != EVP_DecryptFinal_ex(ctx, buf + newlen, &newlen)) {
		EVP_CIPHER_CTX_free(ctx);
		return 0;
	}
	
	EVP_CIPHER_CTX_free(ctx);
	len += newlen;
	buf[len] = '\0';
	return len;
}