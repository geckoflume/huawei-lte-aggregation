/**
 * @file netutils.c
 * @author Florian Mornet (Florian.Mornet@bordeaux-inp.fr)
 * @brief 
 * @version 0.1
 * @date 2020-12-29
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include "netutils.h"

int socket_connect(const char *host)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    if ((hp = gethostbyname(host)) == NULL)
    {
        herror("gethostbyname");
        exit(1);
    }
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

    if (sock == -1)
    {
        perror("setsockopt");
        exit(1);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        perror("connect");
        exit(1);
    }
    return sock;
}

int socket_close(int fd)
{
    shutdown(fd, SHUT_RDWR);
    return close(fd);
}

ssize_t http_get(int fd, const char *host)
{
    char request[MAX_REQUEST_LEN];
    int len = snprintf(request, MAX_REQUEST_LEN, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host);
    return write(fd, request, len);
}

ssize_t http_post_login(int fd, const char *host, const char *sessionid, const char *csrf, const char* encoded_password)
{
    char request[MAX_REQUEST_LEN];
    int len = snprintf(request, MAX_REQUEST_LEN, "POST /api/user/login HTTP/1.1\r\nHost: %s\r\nCookie: SessionID=%s\r\nContent-Type: application/xml\r\n__RequestVerificationToken: %s\r\nContent-Length: 225\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\" ?><request><Username>admin</Username><Password>%s</Password><password_type>4</password_type></request>", host, sessionid, csrf, encoded_password);
    return write(fd, request, len);
}

ssize_t http_get_csrf(int fd, const char *host, const char *sessionid, const char *csrf)
{
    char request[MAX_REQUEST_LEN];
    int len = snprintf(request, MAX_REQUEST_LEN, "GET /api/webserver/SesTokInfo HTTP/1.1\r\nHost: %s\r\nCookie: SessionID=%s\r\n__RequestVerificationToken: %s\r\n\r\n", host, sessionid, csrf);
    return write(fd, request, len);
}

ssize_t http_post_band(int fd, const char *host, const char *sessionid, const char *csrf, const char* band)
{
    char request[MAX_REQUEST_LEN];
    int len = snprintf(request, MAX_REQUEST_LEN, "POST /api/net/net-mode HTTP/1.1\r\nHost: %s\r\nCookie: SessionID=%s\r\nContent-Type: application/xml\r\n__RequestVerificationToken: %s\r\nContent-Length: 148\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\" ?><request><NetworkMode>03</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>%s</LTEBand></request>", host, sessionid, csrf, band);
    return write(fd, request, len);
}