/**
 * @file netutils.h
 * @author Florian Mornet (Florian.Mornet@bordeaux-inp.fr)
 * @brief Network-related functions to connect to Huawei routers using sockets.
 * @version 0.1
 * @date 2020-12-29
 *
 * @copyright Copyright (c) 2020. This is free software, licensed under the GNU General Public License v3.
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
 * @brief Print a message on stderr and exit with a failure status code.
 *
 * @param message String to be displayed on stderr
 */
void exit_failure(const char *message);

/**
 * @brief Open a new socket to a host and return the associated file desciptor.
 *
 * @param[in] host IP to connect to
 * @return File descriptor for the opened socket, or -1 on error
 */
int socket_connect(const char *host);

/**
 * @brief Shut down connection and close a specified socket.
 *
 * @param[in] fd File descriptor representing the socket to close
 * @return 0 on success, -1 on error
 */
int socket_close(int fd);

/**
 * @brief Send a HTTP GET request to / on the fd socket
 *
 * @param[in] fd File descriptor representing the socket
 * @param[in] host IP to connect to
 * @return Number of bytes written to the file descriptor, or -1 on error
 */
ssize_t http_get_home(int fd, const char *host);

/**
 * @brief Send a HTTP POST request to /api/user/login with specified header data to login.
 *
 * @param[in] fd File descriptor representing the socket
 * @param[in] host IP to connect to
 * @param[in] sessionid SessionID fetched from http_get_home()
 * @param[in] csrf CSRF token fetched from http_get_home()
 * @param[in] encoded_password Encoded password, @see encode_password()
 * @return Number of bytes written to the file descriptor, or -1 on error
 */
ssize_t http_post_login(int fd, const char *host, const char *sessionid, const char *csrf,
                        const char *encoded_password);

/**
 * @brief Send a HTTP GET request to /api/webserver/SesTokInfo with specified header data to get a new CSRF token.
 *
 * @param[in] fd File descriptor representing the socket
 * @param[in] host IP to connect to
 * @param[in] sessionid SessionID fetched from http_get_home()
 * @param[in] csrf CSRF token fetched from http_get_home()
 * @return Number of bytes written to the file descriptor, or -1 on error
 */
ssize_t http_get_csrf(int fd, const char *host, const char *sessionid, const char *csrf);

/**
 * @brief Send a HTTP POST request to /api/user/login with specified header data to request a network band change.
 *
 * @param[in] fd File descriptor representing the socket
 * @param[in] host IP to connect to
 * @param[in] sessionid SessionID fetched from http_get_home()
 * @param[in] csrf CSRF token fetched from http_get_home() or http_get_csrf()
 * @param[in] band Band in hex format to change to @see ../README.md
 * @return Number of bytes written to the file descriptor, or -1 on error
 */
ssize_t http_post_band(int fd, const char *host, const char *sessionid, const char *csrf, const char *band);