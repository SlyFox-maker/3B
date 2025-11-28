#include "configParser.hpp"
#include "attackManager.hpp"
#include "ddaAttack.hpp"


#include "core/config.hpp"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>    
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <errno.h>

#define DAEMON_SOCKET_PATH "/tmp/mydaemon.sock"

using namespace std;
using namespace config3B;

// ---------------- NFQHandler ----------------
class NFQHandler {
private:
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int queue_num_;
    bool running_;
    unique_ptr<AttackManager> attack_manager_;

public:
    NFQHandler(int queue_num = 0) : queue_num_(queue_num), nfq_handle_(nullptr), queue_handle_(nullptr), running_(true) {}

    ~NFQHandler() {
        stop();
    }
    bool setup_attacks() {
        // Инициализируем менеджер атак с путями к конфигам
        attack_manager_ = std::make_unique<AttackManager>(
            config3B::DPI_CONFIG_NFQWS_MAIN,
            "./configuration/nfqws/attackConfigs.ini"  // или другой путь
        );
        
        // Регистрируем все атаки
        attack_manager_->register_attack("dda", std::make_shared<DDAAttack>());
        
        // Инициализируем систему атак
        return attack_manager_->initialize_all();
    }
    bool init() {
        nfq_handle_ = nfq_open();
        if (!nfq_handle_) { cerr << "[-] nfq_open() failed\n"; return false; }
        if (nfq_unbind_pf(nfq_handle_, AF_INET) < 0) { cerr << "[-] nfq_unbind_pf() failed\n"; nfq_close(nfq_handle_); return false; }
        if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) { cerr << "[-] nfq_bind_pf() failed\n"; nfq_close(nfq_handle_); return false; }
        cout << "[+] Netfilter Queue initialized\n";
        return true;
    }

    bool create_queue() {
        queue_handle_ = nfq_create_queue(nfq_handle_, queue_num_, &packet_handler, this);
        if (!queue_handle_) { cerr << "[-] nfq_create_queue() failed\n"; return false; }
        if (nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF) < 0) { cerr << "[-] nfq_set_mode() failed\n"; return false; }
        cout << "[+] Queue " << queue_num_ << " created\n";
        return true;
    }

    void start() {
        int fd = nfq_fd(nfq_handle_);
        char buffer[4096];
        cout << "[*] Starting packet processing...\n";
        cout << "[*] iptables -I FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num " << queue_num_ << "\n";

        while (running_) {
            int rv = recv(fd, buffer, sizeof(buffer), 0);
            if (rv >= 0) nfq_handle_packet(nfq_handle_, buffer, rv);
            else if (errno != EWOULDBLOCK && errno != EINTR) {
                cerr << "[-] recv() error: " << strerror(errno) << endl;
                break;
            }
        }
    }

    void stop() {
        running_ = false;
        if (queue_handle_) { nfq_destroy_queue(queue_handle_); queue_handle_ = nullptr; }
        if (nfq_handle_) { nfq_close(nfq_handle_); nfq_handle_ = nullptr; }
        cout << "[+] NFQ stopped\n";
    }

    static int packet_handler(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                              struct nfq_data* nfa, void* data) {
        NFQHandler* handler = static_cast<NFQHandler*>(data);
        return handler->process_packet(qh, nfa);
    }

    int process_packet(struct nfq_q_handle* qh, struct nfq_data* nfa) {
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (!ph) return -1;
        uint32_t id = ntohl(ph->packet_id);

        cout << "Пакет #" << id << " получен!" << endl;

        unsigned char* packet_data;
        int len = nfq_get_payload(nfa, &packet_data);
        
        if (len > 0) {
            analyze_packet(packet_data, len, id);
            
            // ДОБАВЬ ПРОВЕРКУ!
            if (attack_manager_) {
                attack_manager_->process_packet(packet_data, len, id);
            } else {
                cout << " Attack manager not initialized!" << endl;
            }
        }
        
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

private:
    void analyze_packet(unsigned char* packet_data, int len, uint32_t id) {
        struct iphdr* ip_header = (struct iphdr*)packet_data;
        if (ip_header->protocol != IPPROTO_TCP) return;

        int ip_header_len = ip_header->ihl * 4;
        struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header_len);

        string src_ip = ip_to_string(ip_header->saddr);
        string dst_ip = ip_to_string(ip_header->daddr);
        uint16_t dst_port = ntohs(tcp_header->dest);

        //cout << "📦 Пакет #" << id << " | " << src_ip << ":" << ntohs(tcp_header->source)
        //     << " → " << dst_ip << ":" << dst_port << " | " << len << " байт\n";

        if (len > ip_header_len + tcp_header->doff * 4) {
            int data_offset = ip_header_len + tcp_header->doff * 4;
            int data_len = len - data_offset;
            if (data_len > 0) extract_domain_info(packet_data + data_offset, data_len, dst_port);
        }

        //cout << endl;
    }

    string ip_to_string(uint32_t ip) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr; addr.s_addr = ip;
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return string(buf);
    }

    void extract_domain_info(unsigned char* data, int len, uint16_t port) {
        string packet_data((char*)data, len);
        if (port == 443 && len > 5 && data[0] == 0x16) { find_tls_sni(data, len); }
        else if (port == 80 || port == 8080) { find_http_host(packet_data); }
        else if (port == 53) { //cout << "   🕵️‍♂️ DNS запрос\n"; 
        }
    }

    void find_tls_sni(unsigned char* data, int len) {
        for (int i = 0; i < len - 5; i++) {
            if (data[i] == 0x00 && data[i+1] == 0x00) {
                uint16_t sni_type = (data[i-1] << 8) | data[i];
                if (sni_type == 0x0000) {
                    uint16_t sni_len = (data[i+3] << 8) | data[i+4];
                    if (i + 5 + sni_len <= len) {
                        string domain((char*)data + i + 5, sni_len);
                        //cout << "   🔒 HTTPS: " << domain << endl;
                        return;
                    }
                }
            }
        }
    }

    void find_http_host(const string& data) {
        size_t host_pos = data.find("Host: ");
        if (host_pos != string::npos) {
            size_t host_end = data.find("\r\n", host_pos);
            if (host_end != string::npos) {
                string host = data.substr(host_pos + 6, host_end - host_pos - 6);
                //cout << "   🌐 HTTP Host: " << host << endl;
            }
        }
    }
};

// ---------------- Main Daemon ----------------
int main() {
    int server_fd, client_fd;
    struct sockaddr_un address;
    char buffer[256];

    // ---- Проверка прав ----
    if(geteuid() != 0) { cerr << "[-] Run as root!\n"; return 1; }

    // ---- NFQ Инициализация ----
    NFQHandler nfq;
    
    // НАСТРОЙКА АТАК ДО ЗАПУСКА ПОТОКА!
    if (!nfq.setup_attacks()) {
        cerr << "[-] Attack system initialization failed\n";
        return -1;
    }
    
    if(!nfq.init() || !nfq.create_queue()) { 
        cerr << "[-] NFQ init failed\n"; 
        return -1; 
    }

    // ---- Unix Socket ----
    unlink(DAEMON_SOCKET_PATH);
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(server_fd < 0) { cerr << "Socket creation failed\n"; return -1; }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, DAEMON_SOCKET_PATH, sizeof(address.sun_path)-1);

    if(bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Bind failed\n"; close(server_fd); return -1;
    }

    listen(server_fd, 5);
    cout << "Hi! Im deamon for do some deamon thinks :)\n";

    // ЗАПУСК ПОТОКА ПОСЛЕ ВСЕХ ИНИЦИАЛИЗАЦИЙ
    thread nfq_thread([&nfq](){ nfq.start(); });

    // ---- Unix Socket loop ----
    while(true) {
        client_fd = accept(server_fd, nullptr, nullptr);
        if(client_fd < 0) { cerr << "Accept failed\n"; continue; }

        memset(buffer, 0, sizeof(buffer));
        read(client_fd, buffer, sizeof(buffer)-1);
        cout << "Received command: " << buffer << endl;

        close(client_fd);

        if(strcmp(buffer, "exit") == 0) {
            cout << "Shutting down daemon.\n";
            break;
        }
    }

    nfq.stop();
    if(nfq_thread.joinable()) nfq_thread.join();
    close(server_fd);
    unlink(DAEMON_SOCKET_PATH);

    return 0;
}

//  https://chat.deepseek.com/a/chat/s/a686b643-495f-4417-8935-2d79ca861907