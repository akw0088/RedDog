#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#ifndef _WIN32
	#include <unistd.h>
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <sys/select.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <pthread.h>
	#include <time.h>
	#include <signal.h>
	#include <fcntl.h>

	#define SOCKET int
	#define SOCKET_ERROR -1
	#define INVALID_SOCKET -1
	#define closesocket close

#endif

#define BUFFER_SIZE 1024 * 1024 * 32
char recv_buffer[BUFFER_SIZE] = {0};
char temp_buffer[BUFFER_SIZE] = {0};
char *gUsername = NULL;
char *gPassword = NULL;



char *strip(char *s)
{
	char *pdata = NULL;
	int i;

	do
	{
		pdata = strstr(s, "&quot;");
		if (pdata == NULL)
			break;

		pdata[0] = '\"';
		for(i = 0; i < strlen(pdata); i++)
		{
			pdata[i+1] = pdata[i+6];
		}
	} while (pdata != NULL);
	return s;
}

char *get_file(char *filename, int *size)
{
	FILE	*file;
	char	*buffer;
	int	file_size, bytes_read;

	file = fopen(filename, "rb");
	if (file == NULL)
		return 0;
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	buffer = (char *)malloc(file_size + 1);
	if (buffer == NULL)
	{
		perror("malloc failed");
		return NULL;
	}
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
		return 0;
	*size = file_size;
	fclose(file);
	buffer[file_size] = '\0';
	return buffer;
}

int tcp_connect(char *ip_str, short int port)
{
        struct sockaddr_in      servaddr;
        SOCKET sock;
	int ret;

	sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(ip_str);
	servaddr.sin_port = htons(port);

	// 3 way handshake
	printf("Attempting to connect to %s\n", ip_str);
	ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
	if (ret == SOCKET_ERROR)
	{
		switch(errno)
		{
		case ETIMEDOUT:
			printf("Fatal Error: Connection timed out.\n");
			break;
		case ECONNREFUSED:
			printf("Fatal Error: Connection refused\n");
			break;
		case EHOSTUNREACH:
			printf("Fatal Error: Router sent ICMP packet (destination unreachable)\n");
			break;
		default:
			printf("Fatal Error: %d\n", ret);
			break;
		}
		return -1;
	}
	printf("TCP handshake completed\n");

	return sock;
}

int copyline(char *dst, const char *src)
{
	int i = 0;

	for(i = 0; i < strlen(src); i++)
	{
		dst[i] = src[i];
		if (src[i] == '\n' || src[i] == '\r' || src[i] == '>')
		{
			dst[i] = '\0';
			return 1;
		}
	}
	return 0;
}

int parse_smtp(int connfd, const char *buff, char *send_to, char *subject, char *body, char *hostname)
{
	char *pdata = NULL;
	char response[1024] = {0};
	static int fbody = 0;
	static int fsubject = 0;
	static int fsendto = 0;
	static int auth = 1;

	if (fbody)
	{
		strcat(body, buff);
	}

	pdata = strstr(buff, "EHLO");
	if (pdata)
	{
		fbody = 0;
		fsubject = 0;
		fsendto = 0;

		sscanf(buff, "EHLO %s", hostname);
		printf("250 Hola\n");
		strcpy(response, "250 Hola\r\n");
		send(connfd, response, strlen(response), 0);
		return 0;
	}

	pdata = strstr(buff, "HELO");
	if (pdata)
	{
		fbody = 0;
		fsubject = 0;
		fsendto = 0;
		sscanf(buff, "HELO %s", hostname);
		printf("250 Hello\n");
		strcpy(response, "250 Hello\r\n");
		send(connfd, response, strlen(response), 0);
		return 0;
	}

	pdata = strstr(buff, "QUIT");
	if (pdata)
	{
		printf("250 Goodbye\n");
		strcpy(response, "250 Goodbye\r\n");
		send(connfd, response, strlen(response), 0);
		closesocket(connfd);
		return -1;
	}



	pdata = strstr(buff, "RCPT TO:");
	if (pdata)
	{
		if (auth)
		{
			if ( copyline(send_to, pdata + 9) )
			{
				printf("Found destination email: %s\n", send_to);
				fsendto = 1;
				strcpy(response, "250 Recipient ok\r\n");
				send(connfd, response, strlen(response), 0);
				return 0;
			}
			else
			{
				printf("copyline failed on destination email\n");
				return 0;
			}
		}
		else
		{
			printf("530 Auth required\n");
			strcpy(response, "530 Auth required\r\n");
			send(connfd, response, strlen(response), 0);
			return 0;
	/*	
			printf("334 VXNlcm5hbWU6\n");
			strcpy(response, "334 VXNlcm5hbWU6\r\n");
			send(connfd, response, strlen(response), 0);
			*/
			return 0;
		}
	}

	pdata = strstr(buff, "MAIL FROM:");
	if (pdata)
	{
		if (auth)
		{
			printf("250 Sender ok\n");
			strcpy(response, "250 Sender ok\r\n");
			send(connfd, response, strlen(response), 0);
			return 0;
		}
		else
		{
			printf("530 Auth required\n");
			strcpy(response, "530 Auth required\r\n");
			send(connfd, response, strlen(response), 0);
			return 0;
		}
	}

	pdata = strstr(buff, "Subject: ");
	if (pdata)
	{
		if ( copyline(subject, pdata + 9) )
		{
			printf("Found subject: %s\n", subject);
			fsubject = 1;
		}
		else
		{
			printf("copyline failed on subject\n");
			return 0;
		}
	}

	pdata = strstr(buff, "DATA");
	if (pdata)
	{
		strcat(body, pdata + 6);
		 printf("Found body\n");
		fbody = 1;
		printf("354 Go ahead\n");
		strcpy(response, "354 Go ahead\r\n");
		send(connfd, response, strlen(response), 0);
		sleep(3); // give recv buffer time to fill up
		return 0;
	}
	if (strstr(buff, ".") != NULL)
	{
		if ( fbody && fsubject && fsendto )
		{
			fbody = 0;
			fsubject = 0;
			fsendto = 0;

			printf("250 Message accepted for delivery\n [%s %s]\n", send_to, subject);
			strcpy(response, "250 Message accepted for delivery\r\n");
			send(connfd, response, strlen(response), 0);
			closesocket(connfd);
			return 1;
		}
	}
	return 0;
}

int parse_email(const char *body, char *message)
{
	char *pdata = NULL;
	char *pdata2 = NULL;
	char boundary[80] = {0};
	char endboundary[80] = {0};
	int i;
	FILE *fp;

	pdata = strstr(body, "boundary=");
	if (pdata == NULL)
	{
		printf("Failed to find boundary designation\n");
		return -1;
	}

	copyline(boundary, pdata + 10);
	boundary[strlen(boundary) - 1] = '\0';
	printf("Boundary = [%s]\n", boundary);

	sprintf(endboundary, "--%s", boundary);

	pdata = strstr(pdata + strlen("boundary=") + strlen(boundary) + 1, boundary);
	if (pdata == NULL)
	{
		printf("Failed to find message boundary\n");
		return -1;
	}

	pdata2 = strstr(pdata+1, endboundary);
	if (pdata2 == NULL)
	{
		printf("Failed to find message end boundary\n");
		return -1;
	}

	pdata += strlen(boundary) + 1;
	pdata = strstr(pdata, "\r\n\r\n");
	if (pdata == NULL)
	{
		printf("Failed to skip headers\n");
		return -1;
	}
	pdata += 4;
	for(i = 0; i < pdata2 - pdata; i++)
	{
		message[i] = pdata[i];
	}
	message[i] = '\0';
	printf("Message is %s\n", message);

	pdata = pdata2;
	pdata2 = strstr(pdata+1, endboundary);
	if (pdata2 == NULL)
	{
		printf("Failed to find data end boundary\n");
		return -1;
	}

	pdata += strlen(boundary) + 1;
	pdata = strstr(pdata, "\r\n\r\n");
	if (pdata == NULL)
	{
		printf("Failed to skip headers\n");
		return -1;
	}

	pdata += 4;


	// These are still base64 encoded
	fp = fopen("./snap1", "wb");
	if (fp == NULL)
	{
		perror("fopen failed");
		return -1;
	}
	printf("Writing attachment 1\n");
	fwrite(pdata, pdata2 - pdata, 1, fp);
	fclose(fp);
	system("cat snap1 | base64 -di > snap1.jpg");

	pdata = pdata2;
	pdata2 = strstr(pdata+1, endboundary);
	if (pdata2 == NULL)
	{
		printf("Failed to find end boundary for second attachment\n");
		return 0;
	}
	pdata += strlen(boundary) + 1;
	pdata = strstr(pdata, "\r\n\r\n");
	if (pdata == NULL)
	{
		printf("Failed to skip headers\n");
		return -1;
	}
	pdata += 4;

	fp = fopen("./snap2", "wb");
	if (fp == NULL)
	{
		perror("fopen failed");
		return -1;
	}

	printf("Writing attachment 2\n");
	fwrite(pdata, pdata2 - pdata, 1, fp);
	fclose(fp);
	system("cat snap2 | base64 -di > snap2.jpg");

	return 0;
}

int send_mail(char *username, char *password, char *ip_str, char *send_to, char *subject, char *body)
{
	const char login_request[1024] = "POST http://awright2009.com/mail/src/redirect.php HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\nlogin_username=%s&secretkey=%s\r\n";
	const char get_request[1024] =   "GET http://awright2009.com/mail/src/compose.php HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n";
	const char upload_request[2048] ="POST http://awright2009.com/mail/src/compose.php HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nContent-Type: multipart/form-data; boundary=---------------------------3036503217484659202080980214\r\nContent-Length: %d\r\n\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachments\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"smtoken\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"startMessage\"\r\n\r\n1\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailprio\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n2097152\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attach\"\r\n\r\nAdd\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nawright\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailbox\"\r\n\r\nINBOX\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"composesession\"\r\n\r\n0\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachfile\"; filename=\"%s\"\r\nContent-Type: image/jpeg\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\n\r\n";

	const char mail_request[1024] = "POST http://awright2009.com/mail/src/compose.php HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: %s\r\nContent-Length: %d\r\n\r\nsend=Send&composesession=0&smtoken=%s&startMessage=1&session=3&mailprio=3&MAX_FILE_SIZE=2097152&mailbox=INBOX&username=awright&send_to=%s&subject=%s&attachments=%s&body=%s\r\n\r\n";

	SOCKET sock;
	char buffer[2 * 8192];
	char *pdata = NULL;
	char *last_pdata = NULL;
	char cookie[128] = {0};
	char smtoken[128] = {0};
	char attachment[8192] = {0};


	int content_length = 0;
	int i;
	int rsize;

	sock = tcp_connect(ip_str, 80);
	if (sock == -1)
	{
		return -1;
	}

	printf("Logging into web interface\n");
	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, "login_username=%s&secretkey=%s\r\n", username, password);
	content_length = strlen(buffer) - 2;
	sprintf(buffer, login_request, ip_str, content_length, username, password);
	printf("->\n%s\n", buffer);
	send(sock, buffer, strlen(buffer) + 1, 0);

	memset(buffer, 0, sizeof(buffer));
	recv(sock, buffer, sizeof(buffer), 0);
	printf("<-\n%s\n", buffer);
	closesocket(sock);

	//Set-Cookie: SQMSESSID=vriglobotglmdpjmknttb3uhi6; path=/mail/
	last_pdata = strstr(buffer, "Set-Cookie: SQMSESSID=");
	while (last_pdata != NULL)
	{
		pdata = last_pdata;
		last_pdata = strstr(last_pdata + 1, "Set-Cookie: SQMSESSID=");
	}

	if (pdata == NULL)
	{
		printf("Login response didnt contain session ID cookie\n");
		return -1;
	}

	pdata += strlen("Set-Cookie: ");
	for(i = 0; i < strlen(pdata); i++)
	{
		cookie[i] = pdata[i];
		if (pdata[i] == ';')
		{
			cookie[i] = '\0';
			break;
		}
	}
	sock = tcp_connect(ip_str, 80);
	if (sock == -1)
	{
		return -1;
	}

	printf("Getting smtoken\n");
	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, get_request, ip_str, cookie);
	printf("->\n%s\n", buffer);
	send(sock, buffer, strlen(buffer) + 1, 0);

	memset(buffer, 0, sizeof(buffer));
	sleep(1);
	recv(sock, buffer, sizeof(buffer), 0);
	printf("<-\n%s\n", buffer);


	//<input type="hidden" name="smtoken" value="c5cRrZJPPi9C" />
	pdata = strstr(buffer, "<input type=\"hidden\" name=\"smtoken\" value=\"");
	if (pdata == NULL)
	{
		printf("Couldnt find smtoken\n");
		return -1;
	}

	pdata += strlen("<input type=\"hidden\" name=\"smtoken\" value=\"") - 1;
	sscanf(pdata, "\"%s\"", &smtoken[0]);
	smtoken[strlen(smtoken)-1] = '\0';
	printf("Using smtoken %s\n", smtoken);
	closesocket(sock);

	sock = tcp_connect(ip_str, 80);
	if (sock == -1)
	{
		return -1;
	}

	char *data = NULL;
	int size = 0;
	data = get_file("snap1.jpg", &size);
	if (data == NULL)
	{
		printf("get_file() failed\n");
		return -1;
	}

	char *content = strstr(upload_request, "\r\n\r\n");
	content += 4;
	sprintf(buffer, "-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachments\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"smtoken\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"startMessage\"\r\n\r\n1\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailprio\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n2097152\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attach\"\r\n\r\nAdd\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nawright\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailbox\"\r\n\r\nINBOX\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"composesession\"\r\n\r\n0\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachfile\"; filename=\"%s\"\r\nContent-Type: image/jpeg\r\n\r\n\r\n-----------------------------3036503217484659202080980214\r\n\r\n", attachment, smtoken, "snap1.jpg");

	content_length = strlen(buffer) + size;

	memset(temp_buffer, 0, sizeof(temp_buffer));
	memset(temp_buffer, '#', size);
	sprintf(recv_buffer, upload_request, ip_str, cookie, content_length, attachment, smtoken, "snap1.jpg", temp_buffer);

	rsize = strlen(recv_buffer);
	pdata = strstr(recv_buffer, "#");
	printf("Uploading attachment\n");
	printf("->\n%s\n", recv_buffer);

	memcpy(pdata, data, size);
	free((void *)data);
	size = 0;
	send(sock, recv_buffer, rsize + 1, 0);

	memset(buffer, 0, sizeof(buffer));
	sleep(3);
	recv(sock, buffer, sizeof(buffer), 0);
	printf("<-\n%s\n", buffer);
	closesocket(sock);

	//<input type="hidden" name="smtoken" value="c5cRrZJPPi9C" />
	pdata = strstr(buffer, "<input type=\"hidden\" name=\"smtoken\" value=\"");
	if (pdata == NULL)
	{
		printf("Couldnt find smtoken\n");
		return -1;
	}

	pdata += strlen("<input type=\"hidden\" name=\"smtoken\" value=\"") - 1;
	sscanf(pdata, "\"%s\"", &smtoken[0]);
	smtoken[strlen(smtoken)-1] = '\0';
	printf("Using smtoken %s\n", smtoken);

	if (strstr(buffer, "snap1.jpg") == NULL)
	{
		printf("Upload failed\n");
		return -1;
	}

	pdata = strstr(buffer, "<input type=\"hidden\" name=\"attachments\" value=\"");
	if (pdata == NULL)
	{
		printf("Couldnt find attachment tag\n");
		return -1;
	}

	pdata += strlen("<input type=\"hidden\" name=\"attachments\" value=\"") - 1;
	sscanf(pdata, "\"%s\"", &attachment[0]);
	attachment[strlen(attachment)-1] = '\0';
	strip(attachment);
	printf("Using attachment %s\n", attachment);

	sock = tcp_connect(ip_str, 80);
	if (sock == -1)
	{
		return -1;
	}

	data = get_file("snap2.jpg", &size);
	if (data == NULL)
	{
		printf("get_file() failed\n");
		return -1;
	}

	sprintf(buffer, "-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachments\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"smtoken\"\r\n\r\n%s\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"startMessage\"\r\n\r\n1\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailprio\"\r\n\r\n3\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n2097152\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attach\"\r\n\r\nAdd\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nawright\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"mailbox\"\r\n\r\nINBOX\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"composesession\"\r\n\r\n0\r\n-----------------------------3036503217484659202080980214\r\nContent-Disposition: form-data; name=\"attachfile\"; filename=\"%s\"\r\nContent-Type: image/jpeg\r\n\r\n\r\n-----------------------------3036503217484659202080980214\r\n\r\n", attachment, smtoken, "snap2.jpg");

	content_length = strlen(buffer) + size;
	memset(temp_buffer, 0, sizeof(temp_buffer));
	memset(temp_buffer, '#', size);
	sprintf(recv_buffer, upload_request, ip_str, cookie, content_length, attachment, smtoken, "snap2.jpg", temp_buffer);

	rsize = strlen(recv_buffer);
	pdata = strstr(recv_buffer, "#");
	printf("Uploading attachment 2\n");
	printf("->\n%s\n", recv_buffer);

	memcpy(pdata, data, size);
	free((void *)data);
	size = 0;
	send(sock, recv_buffer, rsize + 1, 0);

	memset(buffer, 0, sizeof(buffer));
	sleep(3);
	recv(sock, buffer, sizeof(buffer), 0);
	printf("<-\n%s\n", buffer);

	//<input type="hidden" name="smtoken" value="c5cRrZJPPi9C" />
	pdata = strstr(buffer, "<input type=\"hidden\" name=\"smtoken\" value=\"");
	if (pdata == NULL)
	{
		printf("Couldnt find smtoken\n");
		return -1;
	}

	pdata += strlen("<input type=\"hidden\" name=\"smtoken\" value=\"") - 1;
	sscanf(pdata, "\"%s\"", &smtoken[0]);
	smtoken[strlen(smtoken)-1] = '\0';
	printf("Using smtoken %s\n", smtoken);


	if (strstr(buffer, "snap1.jpg") == NULL)
	{
		printf("First upload missing\n");
		exit(0);
		return -1;
	}

	if (strstr(buffer, "snap2.jpg") == NULL)
	{
		printf("Upload failed\n");
		return -1;
	}

	pdata = strstr(buffer, "<input type=\"hidden\" name=\"attachments\" value=\"");
	if (pdata == NULL)
	{
		printf("Couldnt find attachment tag\n");
		return -1;
	}
	pdata += strlen("<input type=\"hidden\" name=\"attachments\" value=\"") - 1;
	sscanf(pdata, "\"%s\"", &attachment[0]);
	attachment[strlen(attachment)-1] = '\0';
	strip(attachment);
	printf("Using attachment %s\n", attachment);





	 last_pdata = strstr(buffer, "Set-Cookie: SQMSESSID=");
	 while (last_pdata != NULL)
	 {
		pdata = last_pdata;
		last_pdata = strstr(last_pdata + 1, "Set-Cookie: SQMSESSID=");
	 }

	 if (pdata == NULL)
	 {
		printf("Login response didnt contain session ID cookie\n");
		return -1;
	 }

	 pdata += strlen("Set-Cookie: ");
	 for(i = 0; i < strlen(pdata); i++)
	 {
		cookie[i] = pdata[i];
		if (pdata[i] == ';')
		{
			 cookie[i] = '\0';
			 break;
		}
	 }

	closesocket(sock);
	sock = tcp_connect(ip_str, 80);
	if (sock == -1)
	{
		return -1;
	}

	sprintf(buffer, "send=Send&composesession=0&smtoken=%s&startMessage=1&session=3&mailprio=3&MAX_FILE_SIZE=2097152&mailbox=INBOX&username=awright&send_to=%s&subject=%s&attachments=%s&body=%s\r\n", smtoken, send_to, subject, attachment, body);
	content_length = strlen(buffer) - 1;

	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, mail_request, ip_str, cookie, content_length, smtoken, send_to, subject, attachment, body);
	printf("Sending MAIL request\n");
	printf("->\n%s\n", buffer);
	send(sock, buffer, strlen(buffer) + 1, 0);

	memset(buffer, 0, sizeof(buffer));
	sleep(1);
	recv(sock, buffer, sizeof(buffer), 0);
	printf("<-\n%s\n", buffer);
	remove("snap1.jpg");
	remove("snap1");
	remove("snap2.jpg");
	remove("snap2");

	closesocket(sock);
	return 0;
}

int listen_request()
{
	int			connfd;
	unsigned int		size = sizeof(struct sockaddr_in);
	struct sockaddr_in	servaddr, client;
	time_t			ticks;
	int listenfd;
	int rcv_size = BUFFER_SIZE;

#ifdef _WIN32
	WSADATA		WSAData;

	WSAStartup(MAKEWORD(2,0), &WSAData);
#endif

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
	{
		 perror("socket error");
		 return 0;
	}

	if ( setsockopt(listenfd, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(rcv_size)) != 0)
	{
		perror("Failed to set receive buffer size");
		return 0;
	}


	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family	 = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port	 = 65535;	/* daytime server */

	if ( (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) == -1 )
	{
		 perror("bind error");
		 return 0;
	}
	printf("Server listening on: %s:%d\n", inet_ntoa(servaddr.sin_addr), htons(servaddr.sin_port));

	if ( listen(listenfd, 3) == -1 )
	{
		 perror("listen error");
		 return 0;
	}

	for (;;)
	{
		char send_to[1024] = {0};
		char subject[1024] = {0};
		char hostname[1024] = {0};
		char response[1024] = {0};

		printf("listening for connections...\n");
		connfd = accept(listenfd, (struct sockaddr *)&client, &size);
		if (connfd == INVALID_SOCKET)
			continue;

		ticks = time(NULL);
		snprintf(response, sizeof(response), "%.24s\r\n", ctime(&ticks));
		printf("Client: %s - %s", inet_ntoa(client.sin_addr), response);

		printf("220 smtp.awright2009.com ESMTP\n");
		strcpy(response, "220 smtp.awright2009.com ESMTP\r\n");
		send(connfd, response, strlen(response), 0);

		fcntl(connfd, F_SETFL, O_NONBLOCK);
		while (1)
		{
			fd_set fdset;
			memset(recv_buffer, 0, BUFFER_SIZE);
			struct timeval timeout = { 15, 0 };
			int ret = 0;

			FD_ZERO(&fdset);
			FD_SET(connfd, &fdset);
			ret = select(connfd + 1, &fdset, NULL, NULL, &timeout);
			if (ret < 0)
			{
				perror("select() failed\n");
				closesocket(connfd);
				break;
			}
			else if (ret == 0)
			{
				printf("select() timed out\n");
				closesocket(connfd);
				break;
			}
			else
			{
				printf("select returned socket as readable\n");
			}

			ret = recv(connfd, recv_buffer, BUFFER_SIZE, 0);
			if (ret > 0)
			{
				printf("<-\n%s", recv_buffer);
				ret = parse_smtp(connfd, recv_buffer, send_to, subject, temp_buffer, hostname);

				if ( ret == -1)
				{
					break;
				}
				else if (ret == 1)
				{
					char message[4096] = {0};

					strcat(message, hostname);
					strcat(message, ": ");
					if (parse_email(temp_buffer, &message[strlen(message)]) == 0)
					{
						send_mail(gUsername, gPassword, "54.213.22.127", send_to, subject, message);
						printf("Sent email after dot, listening for connections\n");
					}
					break;
				}

			}
		}
	}
	return 0;

}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s <username> <password>\n", argv[0]);
		return 0;
	}

	gUsername = argv[1];
	gPassword = argv[2];
	listen_request();
	return 0;
}
