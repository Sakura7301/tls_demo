#define SOCKET_ERROR 	            -1
#define SOCKET 			            int
#define SERVER_PORT                 8888
#define SERVER_ADDR                 "127.0.0.1"
#define MAXBUF                      2048

#define CA_CERT_PATH  	            "./certs/root"
#define SERVER_CERT_PATH            "./certs/server/server.crt"
#define SERVER_KEY  		        "./certs/server/server_private.key"
#define CLIENT_CERT_PATH 			"./certs/client/client.crt"
#define CLIENT_KEY  			    "./certs/client/client_private.key"
#define SECURE_CIPHER_LIST          "HIGH:!RC4:!MD5:!aNULL:!eNULL:!NULL:!DH:!EDH:!EXP:+MEDIUM"

#define SSL_ONE_WAY_AUTH             2