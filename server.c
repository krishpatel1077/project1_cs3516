#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h> // for time functions

#define PORT "7099" // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold
#define MAXDATASIZE 100 // max number of bytes we can get at once

///starter code used from beej's guide to network programming

// Function to log administrative activities
void log_activity(const char *action, const char *client_ip) {
    time_t current_time;
    struct tm *time_info;
    char time_str[20];
    FILE *log_file;

    // Get current time
    time(&current_time);
    time_info = localtime(&current_time);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);

    // Open the log file in append mode, create if it doesn't exist
    log_file = fopen("admin_log.txt", "a+");
    if (log_file == NULL) {
        perror("Error opening log file");
        return;
    }

    // Write log entry to file
    fprintf(log_file, "----\n%s %s %s\n", time_str, action, client_ip);
    fclose(log_file);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// SIGCHLD handler to reap zombie processes
void sigchld_handler(int s) {
    // Wait for all dead processes
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// get size of inputted file
off_t get_file_size(char* file) {
    struct stat buf; 

    if(stat(file, &buf) == -1) {
        perror("Get file size:");
        exit(EXIT_FAILURE);
    }

    return buf.st_size; 
 }

// Function to receive data from client and write it to a file
FILE* receive_and_write(int sockfd) {
    // Receive the length of the data
    off_t length;
    if (recv(sockfd, &length, sizeof(off_t), 0) == -1) {
        perror("recv length");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for receiving buffer
    char buffer[MAXDATASIZE];

    // Open a file to write the received data
    FILE *file = fopen("received_data.png", "wb");
    if (file == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    u_int32_t bytesReceivedSoFar = 0;
    while (bytesReceivedSoFar < length) {
        // Receive data from the client
        int bytesActuallyReceived = recv(sockfd, buffer, MAXDATASIZE, 0);
        if (bytesActuallyReceived == -1) {
            perror("recv data");
            exit(EXIT_FAILURE);
        }

        // Write received data to the file
        fwrite(buffer, 1, bytesActuallyReceived, file);

        bytesReceivedSoFar += bytesActuallyReceived;
    }
    printf("server: received %d bytes of sent file\n", bytesReceivedSoFar);

    // Close the file
    fclose(file);

    return file; 
}

int main(void) {
    int sockfd, new_fd, numbytes; // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    char buf[MAXDATASIZE];
    int rv;
    FILE* qrFile; 

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // Loop through all the results and bind to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while (1) { // main accept() loop
        sin_size = sizeof their_addr;

        // New connection established
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        // Print client's address
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
        printf("server: got connection from %s\n", s);

        // Log connection
        log_activity("Connection established", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener

            // Send message to client
            if (send(new_fd, "Hello, world!", 13, 0) == -1) {
                perror("send");
            }

            if ((numbytes = recv(new_fd, buf, 14, 0)) == -1) {
                perror("recv");
                exit(1);
            }
 
            buf[numbytes] = '\0';

            printf("server: received '%s'\n",buf);

            // Write received data to a file
            qrFile = receive_and_write(new_fd);

            //convert received_data.png to QR code, print results to QRresult.txt 
            system("java -cp javase.jar:core.jar com.google.zxing.client.j2se.CommandLineRunner received_data.png > QRresult.txt");
            
            //send url result, size, and return code 

            off_t fileSize; 
            fileSize = get_file_size("QRresult.txt");

            FILE * dataFile;
            dataFile = fopen("received_data.png", "r");

            char sendingBuf [fileSize];
            char sizeBuf [sizeof(off_t)];

            int sendingSize; 
            bzero(sendingBuf, fileSize);

            if (dataFile == NULL) {
                perror("opening file");
                exit(1);
            }

            //send url size first
            if(send(new_fd, &fileSize, sizeof(off_t), 0) == -1) {
                perror("sending url size value");
            }
       
            printf("server: sending the url size %ld\n", fileSize);

            //loop to send actual data 
            while((sendingSize = fread(sendingBuf, 1, fileSize, dataFile)) > 0) {

                if(send(new_fd, sendingBuf, sendingSize, 0) == -1) {
                     perror("sending file");
                }
       
                printf("server: sent %d bytes of url to client\n", sendingSize);
                bzero(sendingBuf, fileSize);
            }

            //we are done sending, so now close socket 
            printf("closing new_fd");
            close(new_fd);

            // Log disconnection
            log_activity("Connection closed", s);

            exit(0);
        }
        close(new_fd); // parent doesn't need this
    }

    return 0;
}
