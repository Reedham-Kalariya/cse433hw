#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
void cal_hmac(unsigned char *mac, char *message)
{
    /* The secret key for hashing */
    const char key[] = "98765432100123456789987654321001";
    /* Change the length accordingly with your chosen hash engine.
    * Be careful of the length of string with the chosen hash engine. For
   example, SHA1 needed 20 characters. */
    unsigned int len = 32;
    /* Create and initialize the context */
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();
    /* Initialize the HMAC operation. */
    HMAC_Init_ex(ctx, SECRET_KEY, strlen(SECRET_KEY), EVP_sha256(), NULL);
    /* Provide the message to HMAC, and start HMAC authentication. */
    HMAC_Update(ctx, (unsigned char*)message, strlen(message));

    /* HMAC_Final() writes the hashed values to md, which must have enough
   space for the hash function output. */
    HMAC_Final(ctx, mac, &len);
    /* Releases any associated resources and finally frees context variable
   */
    HMAC_CTX_free(ctx);

    return;
}
int main(int argc, char * argv[]) {
    // port number to listen on
    const int portNo = 4096;

    // listening socket
    int serverfd;
    // socket for active connection
    int clientfd;

    struct sockaddr_in serv_addr;   // server address info
    socklen_t addrLength = sizeof(serv_addr);
    char serv_ip[32]; // buffer for storing ip address as a string

    struct sockaddr_in client_addr; // client address info
    char client_ip[32]; // buffer for storing ip address as a string

    const int domain = AF_INET; // IPv4
    const int type = SOCK_STREAM; // TCP
    const int protocol = 0; // IP

    char buffer[256]; // message buffer
    unsigned char receivedHMAC[32];
    unsigned char calculatedHMAC[32];

    // create socket
    serverfd = socket(domain, type, protocol);
    if(serverfd < 0) {
        printf("%s\n", "socket creation failed");
        return -1;
    }

    // zero memory in server/client address struct
    memset(&serv_addr, 0, addrLength);
    memset(&client_addr, 0, addrLength);

    // server address struct setup
    serv_addr.sin_family = domain; // IPv4
    serv_addr.sin_addr.s_addr = INADDR_ANY;  // any input address
    serv_addr.sin_port = htons(portNo);

    // bind server program to socket
    int res = bind(serverfd, (struct sockaddr*)&serv_addr, addrLength);
    if(res < 0) {
        printf("%s\n","bind failed");
        return -2;
    }

    inet_ntop(domain, &(serv_addr.sin_addr), serv_ip, 32);
    printf("Binding done with IP: %s, port: %d\n", serv_ip, ntohs(serv_addr.sin_port));

    int queue_length = 3; // buffer up to 3 incoming connection requests

    // listen
    res = listen(serverfd, queue_length);
    if(res < 0) {
        printf("%s\n","listen failure");
        return -3;
    }

    // block until incoming client request is received
    clientfd = accept(serverfd, (struct sockaddr*)&client_addr, &addrLength);
    if(clientfd < 0) {
        printf("%s\n","accept failed");
        return -4;
    }


    inet_ntop(domain, &(serv_addr.sin_addr), serv_ip, 32);
    printf("connection accepted: server with IP: %s, port: %d\n", serv_ip, ntohs(serv_addr.sin_port));

    // grab IP/port from client, convert IP to a string to print
    inet_ntop(domain, &(client_addr.sin_addr), client_ip, 32);
    printf("connection to client: client IP: %s, port: %d\n", client_ip, ntohs(client_addr.sin_port));


    memset(buffer,0,256); // zero message buffer

    unsigned char *decrypted_message;
// Assume allocation for decrypted_message and adequate size
    int decrypted_length = stream_encrypt(buffer, buffer, key, iv, decrypted_message);


    int n = read(clientfd, buffer, 255); // read message from open connection
    if(n < 0) {
        printf("error reading from socket\n");
        return -5;
    }

    printf("message is: %s\n", buffer);

    n = write(clientfd, "i got your message", 18);

    if(n < 0){
        printf("write fail\n");
        return -6;
    }

    close(clientfd);
    close(serverfd);
}
