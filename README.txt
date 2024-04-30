# project1_cs3516
Project 2 CS 3516 - Krish Patel, Ceci Herriman

Our project involves a server and client program where the client can connect to the 
server, send a QR code PNG file, and receive the URL of the QR code. When the client 
program is running and connected to the server, they will first exchange messages.
Then, you will see information about server interactions. You can type the name of the QR 
code, and the server will decode the file and return the URL, if available, or a return code error.
If a file is not a valid QR code, then a server return code failure will be sent. Other 
operations, 'close' and 'shutdown', are used to terminate the client and 
server connections. These commands also return server codes to inform the client on 
what is occuring. 

When running the server program, you can specify the listening port, 
rate limit messages, the number of max users, and the time for time out connections. 
These arguments can be in any order, with the value coming after indicators PORT, RATE, 
MAX USERS, and TIME OUT. Similarly, when running the client program, you can
specify the port by writing the value after the word PORT. The default value of the 
server's port is 2012. 

The project features a security restriction of a max file size of 800KB (to allow for 
our transparent.png file to be sent). For additional security, the server also 
does not process any image file bytes that exceed the size specified by the client. 

Additionally, the server maintains an administrative log that keeps track of 
the time, IP address, and event when a client connects, a server starts up and is listening, 
a URL fetching is successful, a URL fetching failed, and a client disconnects. 

To run the program, type "make" in your terminal. You can also 
run "make clean" and "make all". Then, run ./server or ./client with 
the appropiate arguments mentioned above. 

--Note: 
We understand that this project is incomplete. Three days before the project submission, 
we became aware to parts of the project needed to be implemented that were not explicitly 
stated in the project guidelines. At that time, we only needed to implement sending error codes, 
rate limiting, and small concurrent user functionalities. Due to our misconception of what
and how features of the project were implemented, we had a plan of action that could no 
longer be achieved because we had to spend our time re-doing a lot of our functionality to 
meet the desired performance of the server and client. 

More specifically, we did not read anything specifying that the client needed to interact 
with the program via stdin, so we assumed that the program would take in the file name 
in the arguments, wait for the QR result, and then exit. When we realized this was not the 
case, our implementation plans for everything still needed to be done completely changed. 

We acknowledge the fact that many of the project specifications we missed were on the forum, 
and we mistakenly based the vast majority of our project and guidelines planning on the 
Project 2 resources page when we should have looked into forum posts before planning. 

If more time was available, error fixes in the "shutdown" implementation, finalization of the 
"timeout" feature, and a fix to a small IP printing error in the admin log would be finished. 

We kindly ask for this to be graded according to our personal and rubric constraints. It was  
our best forward effort, especially considering the hard deadline and multiple other finals.

