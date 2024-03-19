//
// Created by Reedham Kalariya on 3/18/24.
//
#include <openssl/evp.h>

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;
/* Create and initialize the context */
    ctx = EVP_CIPHER_CTX_new();
/* Initialize the decryption operation. */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
/* Initialize key and IV */
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
/*
* Provide any AAD data. This can be called zero or more times as
* required
*/
    if(aad & aad_len > 0){
        EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

    }
/*
* Provide the message to be decrypted, and obtain the plaintext
output.
* EVP_DecryptUpdate can be called multiple times if necessary
*/
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
/*
* Finalize the decryption. A positive return value indicates success,
* and anything else is a failure - the plaintext is not trustworthy.
*/
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
/* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0) {
/* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
/* Verify failed */
        return -1;
    }
}