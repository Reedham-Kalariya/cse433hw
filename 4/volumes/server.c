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

int main() {
    int serverfd, clientfd;
    struct sockaddr_in serv_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned char buffer[BUFFER_SIZE + TAG_LENGTH]; // To read both ciphertext and tag

    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(4096);

    if (bind(serverfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    listen(serverfd, 3);

    printf("Server is listening...\n");

    clientfd = accept(serverfd, (struct sockaddr*)&client_addr, &client_len);
    if (clientfd < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected.\n");

    unsigned char key[KEY_LENGTH] = "01234567899876543210012345678998";
    unsigned char iv[IV_LENGTH] = "0123456789AB";
    unsigned char tag[TAG_LENGTH];
    unsigned char ciphertext[BUFFER_SIZE];
    unsigned char plaintext[BUFFER_SIZE];
    unsigned char aad[] = "ThisIsAdditionalData";
    int aad_len = sizeof(aad) - 1;

    int ciphertext_len = read(clientfd, ciphertext, BUFFER_SIZE);
    if (ciphertext_len < 0) {
        printf("Error reading ciphertext from socket\n");
        return -1;
    }

    int tag_len = read(clientfd, tag, TAG_LENGTH);
    if (tag_len < 0) {
        printf("Error reading tag from socket\n");
        return -1;
    }

    int plaintext_len = gcm_decrypt(ciphertext, ciphertext_len, aad, aad_len, tag, key, iv, IV_LENGTH, plaintext);
    if (plaintext_len < 0) {
        printf("Decryption failed\n");
        return -1;
    }

    printf("Decrypted message: %s\n", plaintext);

    write(clientfd, "Message received and decrypted", 30);
    close(clientfd);
    close(serverfd);

    return 0;
}