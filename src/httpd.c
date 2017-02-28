/* A TCP echo server.
 *
 * Receive a message on port 32000, turn it into upper case and return
 * it to the sender.
 *
 * Copyright (c) 2016, Marcel Kyas
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Reykjavik University nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MARCEL
 * KYAS NOR REYKJAVIK UNIVERSITY BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gprintf.h>

#include <time.h>
#include <sys/time.h>

const int IP_LENGTH = 15;
const int MAX_CLIENTS = 256;
const int REQUEST_BUFFER_SIZE = 65536;
const int BODY_BUFFER_SIZE = 8192;
const int EMPTY_CONNECTION = 0;
const unsigned long TIMEOUT = 30;
const char log_file[] = "log";
const gchar * const recognized_sites[] = { "/", "", "/test", "/color", NULL }; /* These are the only recognized sites, if you try to connect to any others you will get a 404 error */

struct client {
    unsigned long timestamp;
    int fd;
};

/* Taken from http://stackoverflow.com/questions/2726975/how-can-i-generate-an-rfc1123-date-string-from-c-code-win32 */
char * rfc1123_timestamp()
{
    const int RFC1123_TIME_LEN = 29;
    char * buffer = malloc(RFC1123_TIME_LEN + 1);
    memset(buffer, 0, RFC1123_TIME_LEN + 1);

    time_t t = time(NULL);
    struct tm *my_tm = gmtime(&t);
    strftime(buffer, RFC1123_TIME_LEN, "%a, %d %b %Y %H:%M:%S GMT", my_tm);
    return buffer;
}

/* Log the response to the file specified by log_file in append mode so we don't lose past information */
void log_request(struct in_addr sin_addr, in_port_t sin_port, char * request_method, char * request_url, int response_code) {
    FILE * file = fopen(log_file, "a");

    GTimeVal current_time;
    g_get_current_time(&current_time);
    gchar * datestring = g_time_val_to_iso8601(&current_time);
    fprintf(file, "%s : %s:%hu %s %s : %d\n",
            datestring,
            inet_ntoa(sin_addr),
            sin_port,
            request_method,
            request_url,
            response_code);
    g_free(datestring);
    fclose(file);
}

void destroy_ptr(gpointer p) {
    g_free(p);
}

void remove_whitespace(gchar * str) {
    int front = 0, back = strlen(str) - 1, pos, take;
    while (g_ascii_isspace(str[front]))
        front++;
    while (g_ascii_isspace(str[back]))
        back--;
    for (pos = 0, take = front; take <= back; pos++, take++) {
        str[pos] = str[take];
    }
    str[pos] = '\0';
}

void parse_header(GHashTable * field_value_table, gchar ** header_fields) {
    fprintf(stdout, "Parsing header fields...\n");
    for(int i = 1; header_fields[i] != NULL; i++) {
        fprintf(stdout, "%d. %s\n", i, header_fields[i]);
        gchar ** split_field_value = g_strsplit(header_fields[i], ":", -1);
        /* Shift white-space so we dont see it */
        remove_whitespace(split_field_value[0]);
        remove_whitespace(split_field_value[1]);
        g_hash_table_insert(field_value_table, split_field_value[0], split_field_value[1]);
        g_free(split_field_value);
    }
}

/* Returns 0 if there are no query parameters, 1 if there are and -1 if there are problems with parsing */
int parse_uri(GHashTable * query_parameters, gchar * url_query) {
    fprintf(stdout, "Parsing uri...\n");

    int error = 0;
    /* url_query should be like "a=b&c=2%26" */
    if (url_query == NULL) {
        return 0;
    }
    gchar ** parameters = g_strsplit(url_query, "&", -1);
    /* parameters should be like { "a=b", "c=2%26", NULL } */
    for (int i = 0; parameters[i] != NULL; i++) {
        gchar ** key_value = g_strsplit(parameters[i], "=", -1);
        /* key_value should be like { "c", "2%26", NULL } */
        if (key_value[0] == NULL) {
            error = 1;
            g_strfreev(key_value);
            break;
        }
        gchar * key = g_uri_unescape_string(key_value[0], NULL);
        if (key == NULL) {
            error = 1;
            g_strfreev(key_value);
            break;
        }
        g_hash_table_insert(query_parameters,
                            key,
                            g_uri_unescape_string(key_value[1], NULL));
        g_strfreev(key_value);
    }
    g_strfreev(parameters);
    return !error ? 1 : -1;
}

/* Creates initial haeader string */
gchar * init_header(gchar * status_code, gchar * status_message) {
    gchar * timestamp = rfc1123_timestamp();
    gchar * result = g_strdup_printf("%s %s %s\r\n%s%s\r\n",
                                     "HTTP/1.1", status_code, status_message,
                                     "Date: ", timestamp);
    g_free(timestamp);
    return result;
}

/* Takes old header and appends one field and its value. Not time efficient. */
gchar * append_header(gchar * old_header, gchar * field, gchar * value) {
    gchar * result = g_strdup_printf("%s%s: %s\r\n",
                                     old_header,
                                     field, value);
    g_free(old_header);
    return result;
}

/* Takes old header and appends one field and its value (int). Not time efficient. */
gchar * append_header_int(gchar * old_header, gchar * field, int value) {
    gchar * result = g_strdup_printf("%s%s: %d\r\n",
                                     old_header,
                                     field, value);
    g_free(old_header);
    return result;
}

/* Takes old header and appends one cookie and its value. Not time efficient. */
gchar * append_header_cookie(gchar * old_header, gchar * cookie_name, gchar * cookie_value) {
    gchar * result = g_strdup_printf("%sSet-Cookie: %s=%s\r\n",
                                     old_header,
                                     cookie_name, cookie_value);
    g_free(old_header);
    return result;
}

/* Creates HTML5 body for response */
void write_html5_body(gchar * buffer, int max_size, gchar * body) {
    g_snprintf(buffer, max_size, "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
               "<!DOCTYPE html>",
               "<html>",
               "<head>",
               "<meta charset=\"US-ASCII\">",
               "<title>Fast HTTP</title>",
               "</head>",
               body,
               "</html>");
}

int is_url(gchar * url, const gchar * cmp_url) {
    return g_strcmp0(url, cmp_url) == 0 ||
    (strlen(url) == strlen(cmp_url) + 1 && strncmp(url, cmp_url, strlen(cmp_url)) == 0 && url[strlen(url) - 1] == '/');
}

/* Checks for timeout */
int timed_out(unsigned long connection_time) {
    unsigned long now = time(NULL);
    if (now - connection_time >= TIMEOUT) {
        return 1;
    }
    return 0;
}

/* Closes the connection conn and returns first non-zero return value (or 0 if nothing fails) */
int close_conn(struct client * conn) {
    int error = 0;
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    getpeername(conn->fd, (struct sockaddr*) &client, &len);
    fprintf(stdout, "Closing connection from %s:%hu\n", inet_ntoa(client.sin_addr), client.sin_port);
    int retval = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, &len);

    if (error == 0 && retval == 0) {
        retval = shutdown(conn->fd, SHUT_RDWR);
    }
    if (retval == 0) {
        retval = close(conn->fd);
    }
    conn->fd = EMPTY_CONNECTION;
    conn->timestamp = 0;
    return retval;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stdout, "Please specify port number.\n");
        return 0;
    }

    /* Parse the arguments. */
    short requested_port;
    sscanf(argv[1], "%hd", &requested_port);

    int sockfd;
    struct sockaddr_in server, client;
    char request[REQUEST_BUFFER_SIZE];

    /* Create and bind a TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket error, terminating");
        exit(errno);
    }

    /* Network functions need arguments in network byte order instead of
     host byte order. The macros htonl, htons convert the values. */
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(requested_port);

    ssize_t ret = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    if (ret < 0) {
        perror("bind returned an error, terminating");
        exit(errno);
    }

    /* Before the server can accept messages, it has to listen to the
     welcome port. A backlog of MAX_CLIENTS connections is allowed. */
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("listen returned an error, terminating");
        exit(errno);
    }

    struct client clients_array[MAX_CLIENTS];
    memset(&clients_array, 0, sizeof(clients_array));
    fd_set readfds;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients_array[i].fd = EMPTY_CONNECTION;
        clients_array[i].timestamp = 0;
    }


    for (;;) {
        socklen_t len = (socklen_t) sizeof(client);
        int connfd;
        /* Zero out every entry in readfds */
        FD_ZERO(&readfds);
        /* Set the first socket which will accept connections for us */
        FD_SET(sockfd, &readfds);
        int max_fd = sockfd;
        /* Specify maximum select time */
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            struct client curr = clients_array[i];
            if(curr.fd > 0) {
                FD_SET(curr.fd, &readfds);
            }
            if(curr.fd > max_fd) {
                max_fd = curr.fd;
            }
        }
        ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (ret < 0) {
            perror("select error, terminating");
            exit(errno);
        } else if (ret == 0) {
            fprintf(stdout, "No connections received for 30 seconds, still listening on port %hu...\n", requested_port);
            continue;
        }
        if (FD_ISSET(sockfd, &readfds)) // New connection
        {
            if ((connfd = accept(sockfd, (struct sockaddr *) &client, &len)) < 0) {
                perror("accept error, terminating");
                exit(errno);
            }
            fprintf(stdout, "New connection from %s:%hu\n", inet_ntoa(client.sin_addr), client.sin_port);
            for (int i = 0; i < MAX_CLIENTS; i++) // Find available place in clients_array for listening.
            {
                if(clients_array[i].fd == EMPTY_CONNECTION)
                {
                    clients_array[i].fd = connfd;
                    clients_array[i].timestamp = time(NULL);
                    break;
                }
            }
        }
        for (int i = 0; i < MAX_CLIENTS; i++) // For each client connected, check for new requests and handle them in order.
        {
            struct client* conn = &clients_array[i];
            if (conn->fd == EMPTY_CONNECTION) {
                continue;
            }
            if (FD_ISSET(conn->fd, &readfds)) {
                memset(&request, 0, sizeof(request));
                /* Receive from connfd, not sockfd. */
                ssize_t n = recv(conn->fd, request, sizeof(request) - 1, 0);
                if (n == 0) {
                    /* Orderly shutdown of a connection */
                    close_conn(conn);
                    continue;
                } else if (n < 0) {
                    perror("recv returned an error, terminating");
                    exit(errno);
                }
                /* We have received some data from the socket so set the timestamp. Note: that the timestamp is set on the time of handling the request, not receiving. */
                conn->timestamp = time(NULL);
                fprintf(stdout, "*********\nReceived %lu bytes from recv at time %lu.\n", n, conn->timestamp);

                /* *** The great splits *** */
                /* Split request into header and payload and the header into all the lovely fields */
                gchar ** header_body = g_strsplit(request, "\r\n\r\n", -1);
                /* Split header into { "GET / HTTP/1.1", "Host: blabla", "Connection: close", NULL } */
                gchar ** header_fields = g_strsplit(header_body[0], "\r\n", -1);

                /* Split "GET /test HTTP/1.1" into { "GET", "/test",  "HTTP/1.1", NULL } */
                gchar ** split_first_header = g_strsplit(header_fields[0], " ", -1);
                /* This is "GET" or "POST" or something else */
                gchar * request_method = split_first_header[0];
                /* This is "/test" for example */
                gchar * uri = split_first_header[1];
                /* Split "/test?blabla=blablabla" into { "/test", "blabla=blablabla", NULL} */
                gchar ** url_query = g_strsplit(uri, "?", -1);
                /* This is "/test" */
                gchar * request_url = url_query[0];
                /* This is "blabla=blablabla" */
                gchar * url_parameters = url_query[1];

                /* Create hash table to store key value pairs of header fields */
                GHashTable * field_value_table = g_hash_table_new_full (g_str_hash, g_str_equal, destroy_ptr, destroy_ptr);
                parse_header(field_value_table, header_fields);
                fprintf(stdout, "Received %d header field(s).\n", g_hash_table_size(field_value_table));
                /* Do the same thing for uri parameters */
                GHashTable * query_parameters = g_hash_table_new_full (g_str_hash, g_str_equal, destroy_ptr, destroy_ptr);
                int succesful_parse = parse_uri(query_parameters, url_parameters);
                fprintf(stdout, "Received %d query parameter(s).\n", g_hash_table_size(query_parameters));

                /* *** The great splits ends *** */

                /* Verify site */
                int site_not_found = 1;
                for (int i = 0; recognized_sites[i] != NULL; i++) {
                    if (is_url(request_url, recognized_sites[i])) {
                        site_not_found = 0;
                    }
                }

                /* Write the response */
                gchar * header = NULL;
                gchar body[REQUEST_BUFFER_SIZE];
                memset(&body, 0, sizeof(body));
                int body_length = 0;
                /* Save the response code so we can log it later */
                int response_code = 200;

                if (site_not_found) {
                    gchar body_text[BODY_BUFFER_SIZE];
                    memset(&body_text, 0, sizeof(body_text));
                    g_snprintf((gchar *) &body_text, sizeof(body_text), "<body>Site http://%s%s not found.",
                               g_hash_table_lookup(field_value_table, "Host"),
                               request_url);
                    g_sprintf((gchar *) &body_text + strlen(body_text), "</body>");

                    write_html5_body((gchar *) body, sizeof(body), (gchar *) body_text);
                    body_length = strlen(body);
                    header = init_header("404", "Not Found");
                    header = append_header(header, "Content-Type", "text/html");
                    header = append_header_int(header, "Content-Length", body_length);
                    response_code = 404;
                } else if (succesful_parse < 0) { // 400
                    header = init_header("400", "Bad Request");
                    response_code = 400;

                /* If we get this far, no errors 400 errors are sent, yippee */
                } else if (g_strcmp0(request_method, "GET") == 0) {
                    /* Create the body text ex: http://127.0.0.1:12346/ 127.0.0.1:22474 */
                    gchar body_text[BODY_BUFFER_SIZE];
                    memset(&body_text, 0, sizeof(body_text));
                    header = init_header("200", "OK");
                    header = append_header(header, "Content-Type", "text/html");
                    /* Set the background color of /color page according to query parameters */
                    gchar * style = NULL;
                    /* Store the requested color */
                    gchar * query_color = g_hash_table_lookup(query_parameters, "bg");
                    /* If user requests the color url with a color in the query give him that color and set the cookie */
                    if (is_url(request_url, "/color") && query_color != NULL) {
                        style = g_strconcat("style='background-color:", query_color, "'", NULL);
                        header = append_header_cookie(header, "bg", query_color);
                        /* If user requests color url and doesn't put a color in the query try to find a cookie color */
                    } else if (is_url(request_url, "/color") && query_color == NULL) {
                        gchar * cookie = g_hash_table_lookup(field_value_table, "Cookie");
                        if (cookie != NULL) {
                            gchar ** cookie_name_value = g_strsplit(cookie, "=", -1);
                            if (cookie_name_value[1] != NULL) {
                                style = g_strconcat("style='background-color:", cookie_name_value[1], "'", NULL);
                            }
                            g_strfreev(cookie_name_value);
                        }
                    }
                    if (style == NULL) {
                        style = g_strconcat("", NULL);
                    }
                    g_snprintf((gchar *) &body_text, sizeof(body_text), "<body %s>http://%s%s %s:%hu",
                               style,
                               g_hash_table_lookup(field_value_table, "Host"),
                               request_url,
                               inet_ntoa(client.sin_addr),
                               client.sin_port);
                    g_free(style);
                    if (is_url(request_url, "/test")) {
                        /* Iterate over query parameters */
                        GHashTableIter iter;
                        gpointer key, value;

                        g_hash_table_iter_init (&iter, query_parameters);
                        while (g_hash_table_iter_next (&iter, &key, &value)) {
                            g_sprintf((gchar *) &body_text + strlen(body_text), "<p>%s -> %s</p>",
                                      key,
                                      value);
                        }
                    }
                    g_sprintf((gchar *) &body_text + strlen(body_text), "</body>");

                    write_html5_body((gchar *) body, sizeof(body), (gchar *) body_text);
                    body_length = strlen(body);
                    header = append_header_int(header, "Content-Length", body_length);

                } else if (g_strcmp0(request_method, "POST") == 0) {
                    /* If we receive a post request we copy the body of the request back into the response */
                    gchar * data_start = g_strrstr(request, "\r\n\r\n");
                    for (unsigned int i = 4, j = 0; i < n - strlen(header_body[0]); i++, j++) {
                        body[j] = data_start[i];
                    }
                    /* Set the body length as the content length of the request */
                    body_length = strtol(g_hash_table_lookup(field_value_table, "Content-Length"), NULL, 10);

                    header = init_header("200", "OK");
                    header = append_header(header, "Content-Type", "application/octet-stream");
                    header = append_header_int(header, "Content-Length", body_length);

                } else if (g_strcmp0(request_method, "HEAD") == 0) {
                    header = init_header("200", "OK");
                }

                /* Check for keep-alive */
                int keep_alive = 0;
                gchar * conn_val = g_hash_table_lookup(field_value_table, "Connection");
                if (conn_val != NULL && g_ascii_strcasecmp(conn_val, "close") == 0) {
                    keep_alive = 0;
                    header = append_header(header, "Connection", "close");
                } else if (g_ascii_strcasecmp(split_first_header[2], "HTTP/1.0") != 0) {
                    keep_alive = 1;
                } else if (conn_val != NULL && g_ascii_strcasecmp(conn_val, "keep-alive") == 0) {
                    keep_alive = 1;
                    header = append_header(header, "Connection", "keep-alive");
                } else {
                    keep_alive = 0;
                }

                /* Log the request to a log file */
                getpeername(conn->fd, (struct sockaddr*) &client, &len);
                log_request(client.sin_addr, client.sin_port, request_method, request_url, response_code);

                /* Here we put together the response */
                gchar * response_header = g_strconcat(header, "\r\n", NULL);
                gchar response[REQUEST_BUFFER_SIZE];
                memset(response, 0, sizeof(response));
                strcpy(response, response_header);
                memcpy(response + strlen(response_header), body, body_length);

                /* Send the message back. */
                if (send(conn->fd, response, strlen(response_header) + body_length, 0) < 0) {
                    perror("send returned an error");
                    if (close_conn(conn) < 0) {
                        perror("close returned an error, terminating");
                        exit(errno);
                    }
                } else if (keep_alive == 0) {
                    if (close_conn(conn) < 0) {
                        perror("close returned an error, terminating");
                        exit(errno);
                    }
                }

                g_free(header);
                g_free(response_header);
                g_hash_table_destroy(field_value_table);
                g_hash_table_destroy(query_parameters);
                g_strfreev(split_first_header);
                g_strfreev(url_query);
                g_strfreev(header_fields);
                g_strfreev(header_body);

            } else if (timed_out(conn->timestamp)) {
                if (close_conn(conn) < 0) {
                    perror("close returned an error, terminating");
                    exit(errno);
                }
            }
        }
    }
}
