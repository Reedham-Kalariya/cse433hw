//
// Created by Reedham Kalariya on 3/18/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#define BUFFER_SIZE 1024
#define KEY_LENGTH 32 // AES-256 requires a 32 byte key
#define IV_LENGTH 12  // GCM 12 byte IV for efficiency and security
#define TAG_LENGTH 16 // GCM tag length
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
    if(aad != NULL & aad_len > 0){
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
    unsigned char tag[TAG_LENGTH] = {0};
    unsigned char ciphertext[BUFFER_SIZE] = {0};
    unsigned char plaintext[BUFFER_SIZE] = {0};
    unsigned char aad[] = "ThisIsAdditionalData";
    int aad_len = sizeof(aad) - 1;

    int tag_len = read(clientfd, tag, TAG_LENGTH);
    if (tag_len < 0) {
        printf("Error reading tag from socket\n");
        return -1;
    }

    char differentiator;
    int n = read(clientfd, &differentiator, 1);
    if(n < 0 || differentiator != '\n'){
        printf("Error reading differentiator from socket.\n");
        return -1;
    }

    int ciphertext_len = read(clientfd, buffer, BUFFER_SIZE);
    if (ciphertext_len < 0) {
        printf("Error reading ciphertext from socket\n");
        return -1;
    }

    printf("Received ciphertext from buffer.\n");

    int plaintext_len = gcm_decrypt(buffer, BUFFER_SIZE, aad, aad_len, tag, key, iv, IV_LENGTH, plaintext);
    if (plaintext_len < 0) {
        printf("Decryption failed\n");
        return -1;
    }

    printf("Decrypted message: %s\n", plaintext);

    if(write(clientfd, "Message received and decrypted", 30)<0){
        printf("write failed\n");
        return -1;
    }
    close(clientfd);
    close(serverfd);

    return 0;
}