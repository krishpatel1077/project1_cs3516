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
#include <arpa/inet.h>
#include <time.h> // for time functions

#define PORT "7099" // the port client will be connecting to
#define MAXDATASIZE 100 // max number of bytes we can get at once

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

off_t get_file_size(char* file) {
    struct stat buf; 
    if(stat(file, &buf) == -1) {
        perror("Get file size:");
        exit(EXIT_FAILURE);
    }
    return buf.st_size; 
}

int main(int argc, char *argv[]) {
    int sockfd, numbytes;
    char buf[MAXDATASIZE];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    off_t fileSize; 

    if (argc != 3) {
        fprintf(stderr,"usage: client hostname, file\n");
        exit(1);
    }

    // Find file size given the file path
    fileSize = get_file_size(argv[2]);
    printf("Your inputted file size is %ld\n", fileSize);

    memset(&hints, 0, sizeof hints); hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // Loop through all the results and connect to the first we can
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

    // Log connection
    log_activity("Connection established", s);

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

    // Log disconnection
    log_activity("Connection closed", s);

    close(sockfd);
    return 0;
}
