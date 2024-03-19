#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
void cal_hmac(unsigned char *mac, char *message)
{

    /* Change the length accordingly with your chosen hash engine.
    * Be careful of the length of string with the chosen hash engine. For
   example, SHA1 needed 20 characters. */
    unsigned int len = 32;
    /* The secret key for hashing */
    const char key[len] = "98765432100123456789987654321001";
    /* Create and initialize the context */
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create HMAC context\n");
        return;
    }
    /* Initialize the HMAC operation. */
    HMAC_Init_ex(ctx, key, sizeof(key) - 1, EVP_sha256(), NULL));
    /* Provide the message to HMAC, and start HMAC authentication. */
    HMAC_Update(ctx, (unsigned char*)message, strlen(message)));

    /* HMAC_Final() writes the hashed values to md, which must have enough
   space for the hash function output. */
    HMAC_Final(ctx, mac, &len);
    /* Releases any associated resources and finally frees context variable
   */
    printf("HMAC: ");
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", mac[i]);
    }
    printf("\n");
    HMAC_CTX_free(ctx);

    return;
}
int main(int argc, char * argv[]) {
    int clientfd;
    const int serverPort = 4096;

    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    int addrLength = sizeof(server_addr);

    const int domain = AF_INET; // IPv4
    const int type = SOCK_STREAM; // TCP
    const int protocol = 0; // IP

    // create socket
    clientfd = socket(domain, type, protocol);

    if(clientfd < 0) {
        printf("%s\n", "socket creation failed");
        return -1;
    }

    server_addr.sin_family = domain; // IPv4
    // TODO: update IP if needed...
    inet_pton(domain, "10.232.202.246", &(server_addr.sin_addr));
    server_addr.sin_port = htons(serverPort);

    int res = connect(clientfd, (struct sockaddr *)&server_addr, addrLength);
    if(res < 0) {
        printf("%s\n", "connection error");
        return -1;
    }

    // create and zero buffer for sending/receiving messages
    char buffer[256];
    memset(buffer, 0, 256);

    // grab message from user via standard in
    printf("enter a message:\n");
    fgets(buffer, 255, stdin);
//    unsigned char key[KEY_LENGTH];
//    unsigned char iv[IV_LENGTH];
//    memset(key, 'A', KEY_LENGTH);
//    memset(iv, 'B', IV_LENGTH);
    unsigned char *encrypted_message;
    int encrypted_length = cal_hmac((unsigned char *)encrypted_message, buffer);

    // write to the socket
    int n = write(clientfd, buffer, strlen(buffer));
    if(n < 0 ) {
        printf("write failed\n");
        return -1;
    }

    // zero buffer to receive response and read response
    memset(buffer, 0, 256);
    n = read(clientfd, buffer, 255);
    if(n < 0) {
        printf("read error\n");
    }
    // print response
    printf("Server's reponse: %s\n", buffer);

    // Send the HMAC
    if (write(clientfd, encrypted_message, encrypted_length) < 0) {
        printf("HMAC send failed\n");
        return -1;
    }

    printf("Message and HMAC sent.\n");

    close(clientfd);
    return 0;


//    close(clientfd);
}
