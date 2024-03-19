//
// Created by Reedham Kalariya on 3/18/24.
//
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>#include <openssl/evp.h>

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len,ciphertext_len;
/* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
/* Initialize the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
/*
* Set IV length if default 12 bytes (96 bits) is not appropriate
*/
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
/* Initialize key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
/*
* Provide any AAD data. This can be called zero or more times as
* required
*/
    if(aad && aad_len > 0){
        EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
    }
/*
* Provide the message to be encrypted, and obtain the encrypted
output.
* EVP_EncryptUpdate can be called multiple times if necessary
*/
    if (plaintext) {
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    }
/*
* Finalize the encryption. Normally ciphertext bytes may be written at
* this stage, but this does not occur in GCM mode
*/
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
/* Get the tag */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) < 0){
        printf("GCM tag not acquired.\n");
        return -1;
    }
/* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
