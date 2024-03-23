//
// Created by Reedham Kalariya on 3/18/24.
//
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#define KEY_LENGTH 32 // AES-256 requires a 32 byte key
#define IV_LENGTH 12  // GCM 12 byte IV for efficiency and security
#define TAG_LENGTH 16 // GCM tag length

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
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
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

int main(int argc, char * argv[]) {
    int clientfd;
    const int serverPort = 4096;

    struct sockaddr_in server_addr;
    int addrLength = sizeof(server_addr);

    // Create socket
    clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientfd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "10.9.0.6", &(server_addr.sin_addr));
    server_addr.sin_port = htons(serverPort);

    // Connect to server
    if (connect(clientfd, (struct sockaddr *)&server_addr, addrLength) < 0) {
        printf("connection error\n");
        return -1;
    }

    printf("Enter a message:\n");
    unsigned char buffer[1024] = {0};
    fgets((char *)buffer, 1023, stdin);

//    unsigned char tag[16];
//    memset(tag,0,16);
//
    unsigned char key[KEY_LENGTH] = "01234567899876543210012345678998";
    unsigned char iv[IV_LENGTH] = "0123456789AB";
    unsigned char ciphertext[1024] = {0};
    unsigned char tag[TAG_LENGTH] = {0};

    unsigned char aad[] = "ThisIsAdditionalData";
    int aad_len = sizeof(aad) - 1;

    int ciphertext_len = gcm_encrypt((unsigned char *)buffer, 1024, aad, aad_len, key, iv, IV_LENGTH, ciphertext, tag);
    if (ciphertext_len < 0) {
        printf("Encryption failed\n");
        return -1;
    }

    if (write(clientfd, tag, 16) < 0) {
        printf("Error prefixing tag with message to socket.\n");
        return -1;
    }

    char differentiator = '\n';
    if (write(clientfd, &differentiator, 1)<0) {
        printf("Error putting differentiator to socket.\n");
        return -1;
    }

    if(write(clientfd, ciphertext, ciphertext_len) < 0){
        printf("Error writing ciphertext of the message to socket.\n");
        return -1;
    }

    // Send ciphertext and tag to server
    printf("tag: %s",tag);
    printf("ciphertext: %s", ciphertext);
    send(clientfd, ciphertext, ciphertext_len, 0);
    send(clientfd, tag, TAG_LENGTH, 0);

    close(clientfd);
    return 0;
}