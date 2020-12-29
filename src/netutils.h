/**
 * @file netutils.h
 * @author Florian Mornet (Florian.Mornet@bordeaux-inp.fr)
 * @brief 
 * @version 0.1
 * @date 2020-12-29
 * 
 * @copyright Copyright (c) 2020
 * 
 */

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_REQUEST_LEN 1024
#define PORT 80

/**
 * @brief
 *
 * @param host
 * @return int
 */
int socket_connect(const char *host);

/**
 * @brief
 *
 * @param fd
 * @return int
 */
int socket_close(int fd);

/**
 * @brief
 *
 * @param fd
 * @param host
 * @return ssize_t
 */
ssize_t http_get(int fd, const char *host);

/**
 * @brief Perform login POST request
 *
 * @param fd
 * @param host
 * @param sessionid
 * @param csrf
 * @param encoded_password
 * @return ssize_t
 */
ssize_t http_post_login(int fd, const char *host, const char *sessionid, const char *csrf,
                        const char *encoded_password);

/**
 * @brief Get CSRF token
 *
 * @param fd
 * @param host
 * @param sessionid
 * @param csrf
 * @return ssize_t
 */
ssize_t http_get_csrf(int fd, const char *host, const char *sessionid, const char *csrf);

/**
 * @brief Request network band change
 *
 * @param fd
 * @param host
 * @param sessionid
 * @param csrf
 * @param band
 * @return ssize_t
 */
ssize_t http_post_band(int fd, const char *host, const char *sessionid, const char *csrf, const char *band);