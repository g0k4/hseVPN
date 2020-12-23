#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <errno.h>

#define MTU 1500
#define CLIENT 0
#define SERVER 1
#define PORT 55555


int debug = 0;

// функция выводящая информацию о том как использовать данную программу
void help(char *progname) {
    fprintf(stderr, "Usage:\n\
\t%s [-s|-c <server ip>] -p <port> [-h -d]\n\
\t-s: запуск сервера\n\
\t-c: запуск клиента, требуется ip сервера\n\
\t-p: порт(для сервера тот, на котором будет принимать подключения, для клиента - порт сервера)\n\
\t-h: как использовать данную программу\n\
\t-d: вывод откладочной информации\n", progname);
    exit(1);
}

void do_cmd(char *cmd) {
    printf("Execute %s \n", cmd);
    if (system(cmd)) {
        perror(cmd);
        exit(1);
    }
}
// создает заданные интерфейсы в системе
void create_ifr(char *tuntap_name, char *ip) {
    char *cmd = (char *)malloc(((strlen(tuntap_name))+64)*sizeof(char));
    sprintf(cmd, "ip tuntap add %s mode tun", tuntap_name);
    do_cmd(cmd);
    sprintf(cmd, "ip link set %s up", tuntap_name);
    do_cmd(cmd);
    sprintf(cmd, "ip addr add %s/24 dev %s", ip, tuntap_name);
    do_cmd(cmd);
    free(cmd);
}
// удаляем заданный интерфейс из системы
void delete_ifr() {
    do_cmd("ip link delete tun2");
    exit(0);
}

void delete_ifr_sig() {
    struct sigaction sa;
    sa.sa_handler = &delete_ifr;
    sa.sa_flags = SA_RESTART;
    sigfillset(&sa.sa_mask);
    
    if (sigaction(SIGHUP, &sa, NULL) < 0) // закрытии терминала
        perror("sigaction(SIGHUP...) error");
    if (sigaction(SIGINT, &sa, NULL) < 0) // ctrl+c
        perror("sigaction(SIGINT...) error");
    if (sigaction(SIGTERM, &sa, NULL) < 0) // при kill'е
        perror("sigaction(SIGTERM...) error");
}

void perror_exit(char *str) {
    perror(str);
    delete_ifr();
    exit(1);
}

// инициализируем интерфейс и возвращаем его дискриптор
int get_tuntap_fd(char *tuntap_name, int flags) {
    struct ifreq ifr;
    int fd, err;
    if (( fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    strncpy(ifr.ifr_name, tuntap_name, strlen(tuntap_name));

    if ( (err = ioctl(fd,TUNSETIFF, (void *) &ifr)) < -1) {
        perror("ioctl() error");
        close(fd);
        return err;
    }

    return fd;
}

// клиент подкючается к серверу, возвращается дискриптор сокета подключения
int client_connect(char *server_ip, int port) {
    int sock_fd;
    struct sockaddr_in host;
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        perror_exit("Socket() error:");

    memset(&host, 0, sizeof(host));
    host.sin_family = AF_INET; 
    host.sin_addr.s_addr = inet_addr(server_ip);
    host.sin_port = htons(port);

    //подключаемся к серверу
    if (connect(sock_fd, (struct sockaddr*) &host, sizeof(host)) == -1) 
        perror_exit("connect() error");

    if (debug)
        printf("Interface create...\n");
    return sock_fd;
}

// сервер ждет подключения от клиента, вовращает дискриптоорв сокета подключения
int server_listen(int port) {
    struct sockaddr_in remote, local;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
   	    perror_exit("socket()");

    // избавляемся от ошибки address already in use
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0)
        perror_exit("setsockopt()");
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) == -1)
        perror_exit("bind()");
    
    if (listen(sock_fd, 5) < 0)
        perror_exit("listen()");
    
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) == -1)
        perror_exit("accept()");
   
    if (debug)
        printf("Client connected from %s\n", inet_ntoa(remote.sin_addr));
    return net_fd;
}

int main(int argc, char *argv[]) {
    int tun_fd, net_fd, max_fd;
    int n_read, n_write;
    int prog_args;
    char mtu[MTU];
    char remote_ip[16] = "";
    unsigned short int port = PORT;
    int iam; 
    
    if (argc == 1) {
        help(argv[0]);
        exit(1);
    }
    // парсим дополнительные параметры
    while((prog_args = getopt(argc, argv, "sc:p:hd")) > 0){
        switch(prog_args) {
            case 'd':
                debug = 1;
                break;
            case 'h':
                help(argv[0]);
                break;
            case 's':
                iam = SERVER;
                break;
            case 'c':
                iam = CLIENT;
                strncpy(remote_ip,optarg,15);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                help(argv[0]);
      }
    }
    
    // создаем интерфейс
    if (iam == SERVER)
        create_ifr("tun2", "10.0.0.1");
    else
        create_ifr("tun2", "10.0.0.2");

    // удаление интерфейса из системе при прекращении работы
    delete_ifr_sig();
    // инициализируем интерфейс
    if ((tun_fd = get_tuntap_fd("tun2", IFF_TUN | IFF_NO_PI)) < 0) 
        perror_exit("get_tuntap_fd() error");

    net_fd = (iam == SERVER)?server_listen(port):client_connect(remote_ip, port);

    max_fd = (tun_fd > net_fd)?tun_fd:net_fd;

    while(1) {
        int ret;
        fd_set rd_set;
    
        FD_ZERO(&rd_set);
        FD_SET(tun_fd, &rd_set); FD_SET(net_fd, &rd_set);
    
        ret = select(max_fd + 1, &rd_set, NULL, NULL, NULL);
    
        if (ret == -1) {
            if (errno == EINTR)
                continue;
            else
                perror_exit("select()");
        }
    
        // чтение из интерфейса и запись в сокет сервера
        if(FD_ISSET(tun_fd, &rd_set)){
            if ((n_read = read(tun_fd, mtu, MTU)) == -1) 
        	    perror_exit("read tun error");

        	if (debug)
                printf("[TUN->]read %d bytes\n", n_write);
        	// место для шифрования
        	if ((n_write = write(net_fd, mtu, n_read)) == -1) 
        	    perror_exit("send() error");

        	if (debug)
                printf("[->NET]write %d bytes\n", n_write);
        }
        
        // чтение из сокета и запись в интерфейс
        if(FD_ISSET(net_fd, &rd_set)){
            if ((n_read = read(net_fd, mtu, MTU)) == -1)
                perror_exit("recv() error");

            if (debug)
                printf("[NET->]read %d bytes\n", n_read);
        	// место для шифрования
            if ((n_write = write(tun_fd, mtu, n_read)) == -1)
	            perror_exit("read() error");

            if (debug)
                printf("[->TUN]write %d bytes\n", n_write);
        }
    }
  
    return(0);
}
