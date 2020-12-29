/**
 * @file huawei-lte-aggregation.c
 * @author Florian Mornet (Florian.Mornet@bordeaux-inp.fr)
 * @brief Enable Huawei B715s-23 LTE Carrier Aggregation (CA)
 * (by default, specific bands: B28 UL and B28+B7+B3 DL (for french MNO Free Mobile)).
 * @version 0.1
 * @date 2020-12-29
 *
 * @copyright Copyright (c) 2020. This is free software, licensed under the GNU General Public License v3.
 *
 */
#include "base64.h"
#include "netutils.h"
#include "sha256.h"

#define BUFFER_SIZE 1024
#define CSRF_LEN 32
#define SESSIONID_LEN 128
#define BASE64_SHA256_LEN 88
#define ADMIN_USERNAME "admin"
#define ADMIN_USERNAME_LEN 5

/**
 * @brief Convert an ASCII string to its hex representation.
 *
 * @param[out] output Output unsigned char * buffer
 * @param[in] input Input unsigned char * ASCII string
 * @param[in] length Characters count in input
 */
void str_to_hexStr(BYTE *output, BYTE *input, size_t length) {
  size_t i = 0;
  for (; i < length; i++) {
    sprintf((char *)(output + i * 2), "%02x", input[i]);
  }

  // Insert NULL at the end of the output string
  output[i * 2] = '\0';
}

/**
 * @brief Encode a password to the following pattern: base64(sha256("admin"+base64(sha256("pwd"))+"csrf")).
 *
 * @param[out] output Output buffer to store the encoded password
 * @param[in] password Clear text password to login to the router
 * @param[in] csrf Cross-site request forgery string from the first request
 */
void encode_password(unsigned char *output, const char *password, const unsigned char *csrf) {
  int len;
  SHA256_CTX ctx;
  BYTE buf_sha256[SHA256_BLOCK_SIZE + 1];
  BYTE buf_sha256_hex[SHA256_BLOCK_SIZE * 2 + 1];
  BYTE buf_base64[BUFFER_SIZE] = ADMIN_USERNAME;

  // 1: SHA256 encode
  sha256_init(&ctx);
  sha256_update(&ctx, (unsigned char *)password, strlen(password));
  sha256_final(&ctx, buf_sha256);
  buf_sha256[SHA256_BLOCK_SIZE] = '\0';
  str_to_hexStr(buf_sha256_hex, buf_sha256, SHA256_BLOCK_SIZE);
  // printf("SHA256 hex: %s\n", buf_sha256_hex);

  // 2: Base64 encode
  len = base64_encode(buf_sha256_hex, buf_base64 + ADMIN_USERNAME_LEN, SHA256_BLOCK_SIZE * 2, 0);
  len += ADMIN_USERNAME_LEN;

  // 3: Concat admin + password + csrf
  memcpy(buf_base64 + len, (unsigned char *)csrf, CSRF_LEN);
  buf_base64[len + CSRF_LEN] = '\0';

  // 4: SHA256 encode
  sha256_init(&ctx);
  sha256_update(&ctx, buf_base64, len + CSRF_LEN);
  sha256_final(&ctx, buf_sha256);
  buf_sha256[SHA256_BLOCK_SIZE] = '\0';
  str_to_hexStr(buf_sha256_hex, buf_sha256, SHA256_BLOCK_SIZE);

  // 5: Base64 encode in output buffer
  len = base64_encode(buf_sha256_hex, (unsigned char *)output, SHA256_BLOCK_SIZE * 2, 0);
  output[len] = '\0';
}

/**
 * @brief Initialize the connection by sending a first request and parse the router response.
 * @see http_get_home()
 *
 * @param[in] host String representing the router host
 * @param[inout] buffer buffer used to read data from socket
 * @param[out] sessionid buffer to store the SessionID
 * @param[out] csrf buffer to store the CSRF
 * @return true if success
 * @return false otherwise
 */
char init(const char *host, char *buffer, BYTE *sessionid, BYTE *csrf) {
  char csrf_found = 0, sessionid_found = 0;
  char *ptr = NULL;

  int fd = socket_connect(host);
  if (http_get_home(fd, host) == -1)
    exit_failure("HTTP GET /");

  bzero(buffer, BUFFER_SIZE);

  while ((!csrf_found || !sessionid_found) && read(fd, buffer, BUFFER_SIZE - 1) != 0) {
    // Find CSRF token
    if (!csrf_found) {
      ptr = strstr(buffer, "<head><meta name=\"csrf_token\" content");
      if (ptr != NULL) {
        memcpy(csrf, ptr + 39, CSRF_LEN);
        csrf[CSRF_LEN] = '\0';
        ptr = NULL;
        csrf_found = 1;
      }
    }

    // Find SessionID
    if (!sessionid_found) {
      ptr = strstr(buffer, "SessionID=");
      if (ptr != NULL) {
        memcpy(sessionid, ptr + 10, SESSIONID_LEN);
        sessionid[SESSIONID_LEN] = '\0';
        ptr = NULL;
        sessionid_found = 1;
      }
    }

    printf("CSRF found? %d SessionID found? %d\n", csrf_found, sessionid_found);
    bzero(buffer, BUFFER_SIZE);
  }
  socket_close(fd);

  return csrf_found && sessionid_found;
}

/**
 * @brief Send a POST request to login to the router and parse the router response.
 * @see http_post_login()
 *
 * @param[in] host String representing the router host
 * @param[inout] buffer buffer used to read data from socket
 * @param[inout] sessionid buffer containing the SessionID
 * @param[inout] csrf buffer containing the CSRF
 * @param[in] encoded_password buffer containing the encoded password (@see encode_password)
 * @return true if success
 * @return false otherwise
 */
char login(const char *host, char *buffer, BYTE *sessionid, BYTE *csrf, const BYTE *encoded_password) {
  char sessionid_found = 0, token_found = 0, responseOK_found = 0;
  char *ptr = NULL;

  int fd = socket_connect(host);
  if (http_post_login(fd, host, (char *)sessionid, (char *)csrf, (char *)encoded_password) == -1)
    exit_failure("HTTP POST Login");

  while ((!sessionid_found || !token_found || !responseOK_found) && read(fd, buffer, BUFFER_SIZE - 1) != 0) {
    // Find SessionID
    if (!sessionid_found) {
      ptr = strstr(buffer, "SessionID=");
      if (ptr != NULL) {
        memcpy(sessionid, ptr + 10, SESSIONID_LEN);
        sessionid[SESSIONID_LEN] = '\0';
        ptr = NULL;
        sessionid_found = 1;
      }
    }

    // Find __RequestVerificationTokenone
    if (!token_found) {
      ptr = strstr(buffer, "__RequestVerificationTokenone");
      if (ptr != NULL) {
        memcpy(csrf, ptr + 31, CSRF_LEN);
        csrf[CSRF_LEN] = '\0';
        ptr = NULL;
        token_found = 1;
      }
    }

    // Find <response>OK</response>
    if (!responseOK_found) {
      ptr = strstr(buffer, "<response>OK</response>");
      if (ptr != NULL) {
        ptr = NULL;
        responseOK_found = 1;
      }
    }

    printf("SessionID found ? %d __RequestVerificationTokenone found? %d Login OK? %d\n", sessionid_found, token_found,
           responseOK_found);
    bzero(buffer, BUFFER_SIZE);
  }
  socket_close(fd);

  return token_found && responseOK_found;
}

/**
 * @brief Send a GET request to get a new CSRF token and parse the router response.
 * @see http_get_csrf()
 *
 * @param[in] host String representing the router host
 * @param[inout] buffer buffer used to read data from socket
 * @param[in] sessionid buffer containing the SessionID
 * @param[out] csrf buffer containing the new CSRF
 * @param[in] csrf1 buffer containing the RequestVerificationToken CSRF
 * @return true if success
 * @return false otherwise
 */
char get_csrf(const char *host, char *buffer, const BYTE *sessionid, BYTE *csrf, BYTE *csrf1) {
  char csrf_found = 0;
  char *ptr = NULL;

  int fd = socket_connect(host);
  if (http_get_csrf(fd, host, (char *)sessionid, (char *)csrf1) == -1)
    exit_failure("HTTP GET CRSF");

  while (!csrf_found && read(fd, buffer, BUFFER_SIZE - 1) != 0) {
    // Find CSRF token
    if (!csrf_found) {
      ptr = strstr(buffer, "<TokInfo>");
      if (ptr != NULL) {
        memcpy(csrf, ptr + 9, CSRF_LEN);
        csrf[CSRF_LEN] = '\0';
        ptr = NULL;
        csrf_found = 1;
      }
    }

    printf("CSRF found? %d\n", csrf_found);
    bzero(buffer, BUFFER_SIZE);
  }
  socket_close(fd);

  return csrf_found;
}

/**
 * @brief Send a POST request to request a band change and parse the router response.
 * @see http_post_band()
 *
 * @param[in] host String representing the router host
 * @param[inout] buffer buffer used to read data from socket
 * @param[in] sessionid buffer containing the SessionID
 * @param[out] csrf buffer containing the new CSRF
 * @param[in] band Band in hex format to change to @see ../README.md
 * @return true if success
 * @return false otherwise
 */
char band_change(const char *host, char *buffer, const BYTE *sessionid, BYTE *csrf, const char *band) {
  char band_changed = 0;
  char *ptr = NULL;

  int fd = socket_connect(host);
  if (http_post_band(fd, host, (char *)sessionid, (char *)csrf, band) == -1)
    exit_failure("HTTP POST Band change");
  bzero(buffer, BUFFER_SIZE);

  while (!band_changed && read(fd, buffer, BUFFER_SIZE - 1) != 0) {
    // Find <response>OK</response>
    if (!band_changed) {
      ptr = strstr(buffer, "<response>OK</response>");
      if (ptr != NULL) {
        ptr = NULL;
        band_changed = 1;
      }
    }

    printf("Band change to %s OK? %d\n", band, band_changed);
    bzero(buffer, BUFFER_SIZE);
  }
  socket_close(fd);

  return band_changed;
}

int main(int argc, char const *argv[]) {
  char buffer[BUFFER_SIZE];
  BYTE encoded_password[BASE64_SHA256_LEN];
  BYTE sessionid[SESSIONID_LEN + 1];
  BYTE csrf[CSRF_LEN + 1];
  BYTE csrf_new[CSRF_LEN + 1];
  const char *band_ul = "8000000";
  const char *band_dl = "8000044";

  if (argc == 5) {
    band_ul = argv[3];
    band_dl = argv[4];
  }
  if (argc != 3) {
    fprintf(stderr,
            "Usage: %s <huawei-ip> <password> [ul-band] [dl-band]\nExample: %s 192.168.8.1 pass 8000000 8000044\n",
            argv[0], argv[0]);
    exit(EXIT_FAILURE);
  }

  printf("Trying to log in to Huawei B715s-23 at %s...\n", argv[1]);

  char init_success = init(argv[1], buffer, sessionid, csrf);
  if (!init_success)
    exit_failure("CSRF/SessionID");

  encode_password(encoded_password, argv[2], csrf);
  char login_success = login(argv[1], buffer, sessionid, csrf, encoded_password);
  if (!login_success)
    exit_failure("Login");

  char csrf_success = get_csrf(argv[1], buffer, sessionid, csrf_new, csrf);
  if (!csrf_success)
    exit_failure("CSRF1");

  char band_ul_success = band_change(argv[1], buffer, sessionid, csrf_new, band_ul);
  if (!band_ul_success)
    exit_failure("B28 UL");

  csrf_success = get_csrf(argv[1], buffer, sessionid, csrf_new, csrf);
  if (!csrf_success)
    exit_failure("CSRF1");

  char band_dl_success = band_change(argv[1], buffer, sessionid, csrf_new, band_dl);
  if (!band_dl_success)
    exit_failure("B28+B7+B3 DL");

  return EXIT_SUCCESS;
}
