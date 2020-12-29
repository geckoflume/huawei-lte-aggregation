/**
 * @file netutils.c
 * @author Florian Mornet (Florian.Mornet@bordeaux-inp.fr)
 * @brief Network-related functions to connect to Huawei routers using sockets.
 * @version 0.1
 * @date 2020-12-29
 *
 * @copyright Copyright (c) 2020. This is free software, licensed under the GNU General Public License v3.
 *
 */

#include "netutils.h"

void exit_failure(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}

int socket_connect(const char *host) {
  struct hostent *hp;
  struct sockaddr_in addr;
  int on = 1, sock;

  if ((hp = gethostbyname(host)) == NULL)
    exit_failure("gethostbyname");
  bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
  addr.sin_port = htons(PORT);
  addr.sin_family = AF_INET;
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

  if (sock == -1)
    exit_failure("setsockopt");

  if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    exit_failure("connect");
  return sock;
}

int socket_close(int fd) {
  shutdown(fd, SHUT_RDWR);
  return close(fd);
}

ssize_t http_get_home(int fd, const char *host) {
  char request[MAX_REQUEST_LEN];
  int len = snprintf(request, MAX_REQUEST_LEN, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host);
  return write(fd, request, len);
}

ssize_t http_post_login(int fd, const char *host, const char *sessionid, const char *csrf,
                        const char *encoded_password) {
  char request[MAX_REQUEST_LEN];
  int len =
      snprintf(request, MAX_REQUEST_LEN,
               "POST /api/user/login HTTP/1.1\r\nHost: %s\r\nCookie: SessionID=%s\r\nContent-Type: "
               "application/xml\r\n__RequestVerificationToken: %s\r\nContent-Length: 225\r\n\r\n<?xml version=\"1.0\" "
               "encoding=\"UTF-8\" "
               "?><request><Username>admin</Username><Password>%s</Password><password_type>4</password_type></request>",
               host, sessionid, csrf, encoded_password);
  return write(fd, request, len);
}

ssize_t http_get_csrf(int fd, const char *host, const char *sessionid, const char *csrf) {
  char request[MAX_REQUEST_LEN];
  int len = snprintf(request, MAX_REQUEST_LEN,
                     "GET /api/webserver/SesTokInfo HTTP/1.1\r\nHost: %s\r\nCookie: "
                     "SessionID=%s\r\n__RequestVerificationToken: %s\r\n\r\n",
                     host, sessionid, csrf);
  return write(fd, request, len);
}

ssize_t http_post_band(int fd, const char *host, const char *sessionid, const char *csrf, const char *band) {
  char request[MAX_REQUEST_LEN];
  char buffer[MAX_REQUEST_LEN];
  int len = snprintf(
      buffer, MAX_REQUEST_LEN,
      "<?xml version=\"1.0\" encoding=\"UTF-8\" "
      "?><request><NetworkMode>03</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>%s</LTEBand></request>",
      band);
  len = snprintf(request, MAX_REQUEST_LEN,
                 "POST /api/net/net-mode HTTP/1.1\r\nHost: %s\r\nCookie: SessionID=%s\r\nContent-Type: "
                 "application/xml\r\n__RequestVerificationToken: %s\r\nContent-Length: %d\r\n\r\n%s",
                 host, sessionid, csrf, len, buffer);
  return write(fd, request, len);
}