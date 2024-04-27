 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <errno.h>
 #include <string.h>
 #include <netdb.h>
 #include <fcntl.h>
 #include <sys/types.h>
 #include <netinet/in.h>
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <sys/sendfile.h>

 #include <arpa/inet.h>

 #define PORT "7099" // the port client will be connecting to

 #define MAXDATASIZE 100 // max number of bytes we can get at once

 ///starter code used from beej's guide to network programming


 // get sockaddr, IPv4 or IPv6:
 void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
     return &(((struct sockaddr_in*)sa)->sin_addr);
    }

 return &(((struct sockaddr_in6*)sa)->sin6_addr);
 }

 off_t get_file_size(char* file) {
    struct stat buf; 

    if(stat(file, &buf) == -1) {
        perror("Get file size:");
        exit(EXIT_FAILURE);
    }

    return buf.st_size; 
 }

 // Function to receive data from client and print it
 void receive_and_print(int sockfd) {
    // Receive the length of the data
    off_t length;
    if (recv(sockfd, &length, sizeof(off_t), 0) == -1) {
        perror("recv length");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for receiving buffer
    char buffer[MAXDATASIZE];

    u_int32_t bytesReceivedSoFar = 0;
    while (bytesReceivedSoFar < length) {
        // Receive data from the client
        int bytesActuallyReceived = recv(sockfd, buffer, MAXDATASIZE, 0);
        if (bytesActuallyReceived == -1) {
            perror("recv data");
            exit(EXIT_FAILURE);
        }

        // print received data
        printf("%s", buffer);
        
        bytesReceivedSoFar += bytesActuallyReceived;
    }
    printf("server: received %d bytes of sent file\n", bytesReceivedSoFar);

}

 int main(int argc, char *argv[]) {
    int sockfd, numbytes;
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    FILE *qrFile;
    int qrFD;
    off_t sendingOffset; 
    int sentBytes; 
    off_t remainingData;
    int fd; 
    off_t fileSize; 

    if (argc != 3) {
        fprintf(stderr,"usage: client hostname, file\n");
        exit(1);
    }

    //find file size given the file descriptor
    fileSize = get_file_size(argv[2]);
    printf("Your inputted file size is %ld\n", fileSize);    

    memset(&hints, 0, sizeof hints); hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }   

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

    if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    }
 
    buf[numbytes] = '\0';

    printf("client: received '%s'\n",buf);

    if (send(sockfd, "Hello, server!", 14, 0) == -1) {
        perror("send");
    }

    //send file data
    qrFile = fopen(argv[2], "r");
    char sendingBuf [fileSize];
    int sendingSize; 

    bzero(sendingBuf, fileSize);

    if (qrFile == NULL) {
        perror("opening file");
    }

    //send file size first
    if(send(sockfd, &fileSize, sizeof(off_t), 0) == -1) {
        perror("sending file size value");
    }
       
    printf("client: sending the file size %ld\n", fileSize);

    //loop to send actual data 
    while((sendingSize = fread(sendingBuf, 1, fileSize, qrFile)) > 0) {
        if(send(sockfd, sendingBuf, sendingSize, 0) == -1) {
            perror("sending file");
        }
       
        printf("client: sent %d bytes of inputted file to server\n", sendingSize);
        bzero(sendingBuf, fileSize);
    }

    //receive url size and data
    receive_and_print(sockfd);

    //while loop to receive things 
    //while(1) { //end when code 2 is received (timeout)

    //}

    close(sockfd);

    return 0;
}