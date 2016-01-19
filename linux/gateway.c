#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <signal.h>

#include "aes256cbc.h"

#define PIPE_SIZE    32768 // splice pipe buffer size
#define HS_BUFF_SIZE 64    // handshake buffer size
#define MAX_EVENTS   20    // max epoll event for each epoll frame

const char *HS_DONE         = "200"; // handshake finished
const char *HS_WAIT_DONE    = "200"; // handshake request processed but waiting connect to backend
const char *HS_BAD_REQ      = "400"; // incomplete handshake request 
const char *HS_BAD_ADDR     = "401"; // decrypt backend address failed or parse failed
const char *HS_DIAL_ERR     = "500"; // can't connect to backend
const char *HS_DIAL_TIMEOUT = "504"; // connect to backend timeout

// catch SIGTERM
int gw_stop_flag = 0;
void gw_stop(int signal_id) {
   gw_stop_flag = 1;
}

// handshake state
struct gw_hs_state {
	char buf[HS_BUFF_SIZE + 1];
	const char *code;
	int readed;
	int writed;
};

struct gw_conn {
	int fd;
	int pipe[2];
	int events;
	int buffered;
	int deleted;
	struct gw_conn *other;
	struct gw_conn **del_poll;
	struct gw_hs_state *hs_state;
	struct gw_conn *prev;
	struct gw_conn *next;
};

// all connections
struct gw_conn *gw_conn_list;

static struct gw_conn *
gw_add_conn(int pd, int fd, struct gw_conn *del_poll[]) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		fprintf(stderr, "Can't get socket flag - %s\n", strerror(errno));
		return NULL;
	}
	if (fcntl(fd, F_SETFL, flags|O_NONBLOCK) != 0) {
		fprintf(stderr, "Can't set O_NONBLOCK flag - %s\n", strerror(errno));
		return NULL;
	}
	int opt = PIPE_SIZE / 2;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) != 0) {
		fprintf(stderr, "Can't set socket receive buffer - %s\n", strerror(errno));
		return NULL;
	}
	opt = PIPE_SIZE;
	if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) != 0) {
		fprintf(stderr, "Can't set socket send buffer - %s\n", strerror(errno));
		return NULL;
	}
	opt = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) != 0) {
		fprintf(stderr, "Can't set TCP_NODELAY flag - %s\n", strerror(errno));
		return NULL;
	}

	struct gw_conn *conn = (struct gw_conn *)calloc(1, sizeof(struct gw_conn));
	if (conn == NULL) {
		fprintf(stderr, "Can't alloc memory for gw_conn - %s\n", strerror(errno));
		return NULL;
	}
	if (pipe2(conn->pipe, O_NONBLOCK) != 0) {
		fprintf(stderr, "Can't create pipe - %s\n", strerror(errno));
		free(conn);
		return NULL;
	}
	if (fcntl(conn->pipe[1], F_SETPIPE_SZ, PIPE_SIZE) != PIPE_SIZE) {
		fprintf(stderr, "Can't set pipe buffer size - %s\n", strerror(errno));
		goto FAIL;
	}
	conn->fd = fd;
	conn->del_poll = del_poll;
	
	struct epoll_event event;
	event.data.ptr = conn;
	event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
	if (epoll_ctl(pd, EPOLL_CTL_ADD, fd, &event) != 0) {
		fprintf(stderr, "Can't add socket into epoll - %s\n", strerror(errno));
		goto FAIL;
	}
	return conn;
	
FAIL:
	close(conn->pipe[0]);
	close(conn->pipe[1]);
	free(conn);
	return NULL;
}

static void
gw_del_conn(struct gw_conn *conn) {
	if (conn->deleted == 1)
		return;

	struct gw_conn **del_poll = conn->del_poll;
	
	conn->deleted = 1;
	for (int i = 0; i < MAX_EVENTS; i ++) {
		if (del_poll[i] == NULL) {
			del_poll[i] = conn;
			break;
		}
	}
	
	// never happens?
	if (conn->other->deleted == 1)
		return;
		
	conn->other->deleted = 1;
	for (int i = 0; i < MAX_EVENTS; i ++) {
		if (del_poll[i] == NULL) {
			del_poll[i] = conn->other;
			break;
		}
	}
}

static void
gw_free_conn(int pd, struct gw_conn *conn) {
	if (conn->hs_state != NULL) {
		free(conn->hs_state);
	}
	
	struct epoll_event event;
	epoll_ctl(pd, EPOLL_CTL_DEL, conn->fd, &event);
	
	close(conn->fd);
	close(conn->pipe[0]);
	close(conn->pipe[1]);
	free(conn);
}

static void
gw_clean_del_poll(int pd, struct gw_conn *del_poll[]) {
	for (int i = 0; i < MAX_EVENTS; i ++) {
		if (del_poll[i] == NULL)
			break;
		gw_free_conn(pd, del_poll[i]);
		del_poll[i] = NULL;
	}
}

static int
gw_listen(char *addr) {
	int lsn = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK , 0);
	if (lsn < 0) {
		fprintf(stderr, "Can't create listener - %s\n", strerror(errno));
		goto FAIL;
	}
	
	int opt = 1;
	if (setsockopt(lsn, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
		fprintf(stderr, "Can't set SO_REUSEADDR on listener - %s\n", strerror(errno));
		goto FAIL;
	}
	
	// parse address
	char *clone = strchr(addr, ':');
	if (clone == NULL) {
		fprintf(stderr, "Can't parse address - %s\n", addr);
		goto FAIL;
	}
	addr[clone - addr] = '\0';
	struct sockaddr_in lsn_addr;
	lsn_addr.sin_family = AF_INET;
	lsn_addr.sin_port  = htons(atoi(clone + 1));
	lsn_addr.sin_addr.s_addr = inet_addr(addr);
	socklen_t addr_len = sizeof(struct sockaddr_in);
	
	if (bind(lsn, (struct sockaddr *)&lsn_addr, addr_len) != 0) {
		fprintf(stderr, "Can't bind address %s:%s - %s\n", addr, (clone + 1), strerror(errno));
		goto FAIL;
	}
	
	if (listen(lsn, 128) != 0) {
		fprintf(stderr, "Can't listen - %s\n", strerror(errno));
		goto FAIL;
	}
	
	if (getsockname(lsn, (struct sockaddr *)&lsn_addr, &addr_len) != 0) {
		fprintf(stderr, "Can't get listener address - %s\n", strerror(errno));
		goto FAIL;
	}
	
	fprintf(stderr, "Setup proxy at %s:%d\n", inet_ntoa(lsn_addr.sin_addr), ntohs(lsn_addr.sin_port));
	return lsn;
	
FAIL:
	close(lsn);
	return -1;
}

static int
gw_accept(int pd, int lsn, struct gw_conn *del_poll[]) {
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	for (;;) {
		int fd = accept(lsn, &addr, &addr_len);
		if (fd < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return -1;
		}
		struct gw_conn *conn = gw_add_conn(pd, fd, del_poll);
		if (conn == NULL) {
			close(fd);
			continue;
		}
		// setup handshake state
		conn->hs_state = (struct gw_hs_state *)calloc(
			1, sizeof(struct gw_hs_state)
		);
		if (conn->hs_state == NULL) {
			fprintf(stderr, "Can't malloc memory for gw_hs_state - %s", strerror(errno));
			gw_del_conn(conn);
			continue;
		}
	}
	return 0;
}

static void
gw_handshake_in(int pd, struct gw_conn *conn, char *secret) {
	if (!(conn->events & EPOLLIN))
		return;
	
	if (conn->hs_state->code != NULL)
		return;
	
	struct gw_hs_state *state = conn->hs_state;
	
	// read AES256-CBC encrypted address from client side.
	int begin = state->readed;
	while (state->readed < HS_BUFF_SIZE) {
		int n = read(conn->fd, state->buf, HS_BUFF_SIZE - state->readed);
		if (n == 0) {
			state->code = HS_BAD_REQ;
			return;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->events &= ~EPOLLIN;
				break;
			}
			state->code = HS_BAD_REQ;
			return;
		}
		state->readed += n;
	}
	
	// not change
	if (begin == state->readed)
		return;
	
	// make buffer like a c string and search '\n'
	state->buf[state->readed] = '\0';
	if (strchr(state->buf + begin, '\n') == NULL) {
		if (state->readed == HS_BUFF_SIZE - 1) {
			state->code = HS_BAD_REQ;
		}
		return;
	}
	
	// decrypt the backend address
	if (aes256cbc_decrypt(secret, state->buf) == 0) {
		state->code = HS_BAD_ADDR;
		return;
	}
	
	// create a nonblock TCP socket
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		state->code = HS_DIAL_ERR;
		return;
	}
	
	// parse address
	char *clone = strchr(state->buf, ':');
	if (clone == NULL) {
		state->code = HS_BAD_ADDR;
		return;
	}
	state->buf[clone - state->buf] = '\0';
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port  = htons(atoi(clone + 1));
	addr.sin_addr.s_addr = inet_addr(state->buf);
	socklen_t addr_len = sizeof(struct sockaddr_in);

	// connect to backend
	int err = connect(fd, &addr, addr_len);
	if (err < 0 && errno != EINPROGRESS) {
		fprintf(stderr, "Can't connect to backend %s:%s - %s\n", state->buf, clone + 1, strerror(errno));
		close(fd);
		state->code = HS_DIAL_ERR;
		return;
	}
	
	// setup backend connection
	conn->other = gw_add_conn(pd, fd, conn->del_poll);
	if (conn->other == NULL) {
		close(fd);
		state->code = HS_DIAL_ERR;
		return;
	}
	conn->other->other = conn;
	
	// succeed code
	state->code = err == 0 ? HS_DONE : HS_WAIT_DONE;
}

static void
gw_handshake_out(struct gw_conn *conn) {
	struct gw_hs_state *state = conn->hs_state;
	
	if (!(conn->events & EPOLLOUT))
		return;
		
	if (state->code == NULL)
		return;
	
	while (state->writed < 3) {
		int n = write(conn->fd, state->code + state->writed, 3 - state->writed);
		if (n == 0)
			return;
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->events &= ~EPOLLOUT;
				return;
			}
			gw_del_conn(conn);
			return;
		}
		state->writed += n;
	}

	if (state->code == HS_DONE) {
		free(state);
		conn->hs_state = NULL;
	} else {
		gw_del_conn(conn);
	}
}

static int
gw_splice_in(struct gw_conn *conn) {
	while (conn->buffered < PIPE_SIZE) {
		int n = splice(
			conn->fd, NULL, 
			conn->pipe[1], NULL, 
			PIPE_SIZE - conn->buffered, 
			SPLICE_F_MOVE | SPLICE_F_NONBLOCK
		);
		if (n == 0) {
			return -1;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->events &= ~EPOLLIN;
				break;
			}
			return -1;
		}
		conn->buffered += n;
	}
	return 0;
}

static int
gw_splice_out(struct gw_conn *conn) {
	while (conn->other->buffered > 0) {
		int n = splice(
			conn->other->pipe[0], NULL,
			conn->fd, NULL,
			conn->other->buffered,
			SPLICE_F_MOVE | SPLICE_F_NONBLOCK
		);
		if (n == 0) {
			break;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				conn->events &= ~EPOLLOUT;
				break;
			}
			return -1;
		}
		conn->other->buffered -= n;
	}
	return 0;
}

static void
gw_loop(int pd, int lsn, char *secret) {
	// Add the connections that want to close into del_poll and close them at the end of event frame. 
	// Because the connections may be referenced in current event frame.
	struct gw_conn *del_poll[MAX_EVENTS];
	bzero(del_poll, sizeof(struct gw_conn *) * MAX_EVENTS);
	
	struct epoll_event readys[MAX_EVENTS];
	for (;;) {
		int rc = epoll_wait(pd, readys, MAX_EVENTS, -1);
		if (rc < 0) {
			if (errno == EINTR && !gw_stop_flag) {
				continue;
			}
			break;
		}
		for (register int i = 0; i < rc; i ++) {
			// is listener?
			if (readys[i].data.ptr == NULL) {
				if (readys[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
					// TODO: close connections.
					fprintf(stderr, "listener closed\n");
					return;
				}

				if (gw_accept(pd, lsn, del_poll) != 0) {
					// TODO: close connections.
					fprintf(stderr, "listener closed\n");
					return;
				}
				continue;
			}
			
			// save events for EPOLLET
			struct gw_conn *conn = (struct gw_conn *)readys[i].data.ptr;
			conn->events |= readys[i].events;
			
			// deleted by previous event?
			if (conn->deleted == 1)
				continue;
			
			// error happens?
			if (conn->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				// client waiting handshake code?
				if (conn->other != NULL 
				&& conn->other->hs_state != NULL 
				&& conn->other->hs_state->code == HS_WAIT_DONE) {
					conn->other->hs_state->code = HS_DIAL_ERR;
					gw_handshake_out(conn->other);
				} else {
					gw_del_conn(conn);
				}
				continue;
			}
			
			// doing handshake?
			// TODO: read/write timeout
			if (conn->hs_state != NULL) {
				gw_handshake_in(pd, conn, secret);
				gw_handshake_out(conn);
				if (conn->hs_state != NULL)
					continue;
			}
			
			struct gw_conn *other = conn->other;
				
			// client waiting handshake code?
			if (other->hs_state != NULL && other->hs_state->code == HS_WAIT_DONE) {
				other->hs_state->code = HS_DONE;
				gw_handshake_out(other);
			}
			
			// splice in
			if (conn->events & EPOLLIN) {
				if (gw_splice_in(conn) != 0) {
					gw_del_conn(conn);
					continue;
				}
				// because EPOLLET
				if (other->events & EPOLLOUT) {
					if (gw_splice_out(other) != 0) {
						gw_del_conn(other);
						continue;
					}
				}
			}
			
			// splice out
			if (conn->events & EPOLLOUT) {
				if (gw_splice_out(conn) != 0) {
					gw_del_conn(conn);
					continue;
				}
				// because EPOLLET
				if (other->events & EPOLLIN) {
					if (gw_splice_in(other) != 0) {
						gw_del_conn(other);
						continue;
					}
				}
			}
		}
		// close bad connections
		gw_clean_del_poll(pd, del_poll);
	}
}

int
main(int argc, char *argv[]) {
	// the passphrase for AES256-CBC decrypt
	char *secret = getenv("GW_SECRET");
	if (secret == NULL) {
		fprintf(stderr, "Missing GW_SECRET environment variable\n");
		return 1;
	}
	
	int ret = 1;

	// create a nonblock listener
	char *addr = getenv("GW_ADDR");
	if (addr == NULL) {
		addr = strdup("0.0.0.0:0");
	}
	int lsn = gw_listen(addr);
	if (lsn < 0) {
		goto END;
	}
	
	int pd = epoll_create(10);
	if (pd < 0) {
		fprintf(stderr, "Can't create epoll - %s\n", strerror(errno));
		goto END;
	}

	// listener event
	struct epoll_event event;
	event.data.ptr = NULL;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(pd, EPOLL_CTL_ADD, lsn, &event) != 0) {
		fprintf(stderr, "Can't add listener into epoll - %s\n", strerror(errno));
		goto END;
	}
	
	FILE *pid_file = fopen("gateway.pid", "w");
	if (pid_file == NULL || fprintf(pid_file, "%d", getpid()) < 0) {
		fprintf(stderr, "Can't record process ID - %s\n", strerror(errno));
		goto END;
	}
	fclose(pid_file);
	
	// catch SIGTERM
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction *));
	sa.sa_handler = gw_stop;
	sa.sa_flags = 0;
	sigemptyset (&(sa.sa_mask));
	if (sigaction(SIGTERM, &sa, NULL) != 0) {
		fprintf(stderr, "Can't catch SIGTERM signal - %s\n", strerror(errno));
		goto END;
	}
   
	// event loop
	ret = 0;
	fprintf(stderr, "Getway running, pid = %d\n", getpid());
	gw_loop(pd, lsn, secret);
	fprintf(stderr, "Getway killed\n");
	
END:
	// dispose things
	if (addr)    free(addr);
	if (lsn > 0) close(lsn);
	if (pd > 0)  close(pd);
	if (pid_file) remove("gateway.pid");
	return ret;
}