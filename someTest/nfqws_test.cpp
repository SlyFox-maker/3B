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

class NFQHandler {
private:
    struct nfq_handle* nfq_handle_;
    struct nfq_q_handle* queue_handle_;
    int queue_num_;

public:
    NFQHandler(int queue_num = 0) : queue_num_(queue_num), nfq_handle_(nullptr), queue_handle_(nullptr) {}
    
    ~NFQHandler() {
        stop();
    }
    
    bool init() {
        nfq_handle_ = nfq_open();
        if (!nfq_handle_) {
            std::cerr << "[-] nfq_open() failed" << std::endl;
            return false;
        }
        
        if (nfq_unbind_pf(nfq_handle_, AF_INET) < 0) {
            std::cerr << "[-] nfq_unbind_pf() failed" << std::endl;
            nfq_close(nfq_handle_);
            return false;
        }
        
        if (nfq_bind_pf(nfq_handle_, AF_INET) < 0) {
            std::cerr << "[-] nfq_bind_pf() failed" << std::endl;
            nfq_close(nfq_handle_);
            return false;
        }
        
        std::cout << "[+] Netfilter Queue initialized" << std::endl;
        return true;
    }
    
    bool create_queue() {
        queue_handle_ = nfq_create_queue(nfq_handle_, queue_num_, &packet_handler, this);
        if (!queue_handle_) {
            std::cerr << "[-] nfq_create_queue() failed" << std::endl;
            return false;
        }
        
        if (nfq_set_mode(queue_handle_, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
            std::cerr << "[-] nfq_set_mode() failed" << std::endl;
            return false;
        }
        
        std::cout << "[+] Queue " << queue_num_ << " created" << std::endl;
        return true;
    }
    
    void start() {
        int fd = nfq_fd(nfq_handle_);
        char buffer[4096];
        
        std::cout << "[*] Starting packet processing..." << std::endl;
        std::cout << "[*] Run this as root and set iptables rule:" << std::endl;
        std::cout << "[*] iptables -I FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num " << queue_num_ << std::endl;
        std::cout << "[*] Waiting for packets...\n" << std::endl;
        
        while (true) {
            int rv = recv(fd, buffer, sizeof(buffer), 0);
            if (rv >= 0) {
                nfq_handle_packet(nfq_handle_, buffer, rv);
            } else if (errno != EWOULDBLOCK) {
                std::cerr << "[-] recv() error: " << strerror(errno) << std::endl;
                break;
            }
        }
    }
    
    void stop() {
        if (queue_handle_) {
            nfq_destroy_queue(queue_handle_);
            queue_handle_ = nullptr;
        }
        if (nfq_handle_) {
            nfq_close(nfq_handle_);
            nfq_handle_ = nullptr;
        }
        std::cout << "[+] NFQ stopped" << std::endl;
    }
    
    static int packet_handler(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg,
                             struct nfq_data* nfa, void* data) {
        NFQHandler* handler = static_cast<NFQHandler*>(data);
        return handler->process_packet(qh, nfa);
    }
    
    int process_packet(struct nfq_q_handle* qh, struct nfq_data* nfa) {
        struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
        if (!ph) {
            return -1;
        }
        
        uint32_t id = ntohl(ph->packet_id);
        
        unsigned char* packet_data;
        int len = nfq_get_payload(nfa, &packet_data);
        
        if (len > 0) {
            analyze_packet(packet_data, len, id);
        }
        
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

private:
    void analyze_packet(unsigned char* packet_data, int len, uint32_t id) {
        struct iphdr* ip_header = (struct iphdr*)packet_data;
        
        if (ip_header->protocol != IPPROTO_TCP) {
            return; // Пропускаем не-TCP пакеты
        }
        
        int ip_header_len = ip_header->ihl * 4;
        struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header_len);
        
        std::string src_ip = ip_to_string(ip_header->saddr);
        std::string dst_ip = ip_to_string(ip_header->daddr);
        uint16_t dst_port = ntohs(tcp_header->dest);
        
        std::cout << "Пакет #" << id << " | " << src_ip << ":" << ntohs(tcp_header->source);
        std::cout << " → " << dst_ip << ":" << dst_port << " | " << len << " байт" << std::endl;
        
        // Анализируем данные пакета
        if (len > ip_header_len + tcp_header->doff * 4) {
            int data_offset = ip_header_len + tcp_header->doff * 4;
            int data_len = len - data_offset;
            
            if (data_len > 0) {
                extract_domain_info(packet_data + data_offset, data_len, dst_port);
            }
        }
        
        std::cout << std::endl;
    }
    
    std::string ip_to_string(uint32_t ip) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip;
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return std::string(buf);
    }
    
    void extract_domain_info(unsigned char* data, int len, uint16_t port) {
        std::string packet_data((char*)data, len);
        
        // HTTPS (TLS) - ищем SNI
        if (port == 443 && len > 5 && data[0] == 0x16) {
            find_tls_sni(data, len);
        }
        // HTTP - ищем Host header
        else if (port == 80 || port == 8080) {
            find_http_host(packet_data);
        }
        // DNS - можно добавить парсинг DNS запросов
        else if (port == 53) {
            std::cout << "   🕵️‍♂️ DNS запрос" << std::endl;
        }
    }
    
    void find_tls_sni(unsigned char* data, int len) {
        // Упрощенный поиск SNI в TLS handshake
        for (int i = 0; i < len - 5; i++) {
            if (data[i] == 0x00 && data[i+1] == 0x00) {
                // Нашли возможное начало SNI
                uint16_t sni_type = (data[i-1] << 8) | data[i];
                if (sni_type == 0x0000) { // SNI type
                    uint16_t sni_len = (data[i+3] << 8) | data[i+4];
                    if (i + 5 + sni_len <= len) {
                        std::string domain((char*)data + i + 5, sni_len);
                        std::cout << "   🔒 HTTPS: " << domain << std::endl;
                        return;
                    }
                }
            }
        }
        
        // Альтернативный метод поиска домена
        for (int i = 0; i < len - 10; i++) {
            if (is_valid_domain_start(data[i]) && is_valid_domain_char(data[i+1])) {
                int domain_len = 0;
                while (i + domain_len < len && is_valid_domain_char(data[i + domain_len])) {
                    domain_len++;
                }
                if (domain_len > 4 && domain_len < 100) { // Реальные домены
                    std::string domain((char*)data + i, domain_len);
                    if (domain.find('.') != std::string::npos) {
                        std::cout << "   🔍 Возможный домен: " << domain << std::endl;
                        return;
                    }
                }
            }
        }
    }
    
    void find_http_host(const std::string& data) {
        size_t host_pos = data.find("Host: ");
        if (host_pos != std::string::npos) {
            size_t host_end = data.find("\r\n", host_pos);
            if (host_end != std::string::npos) {
                std::string host = data.substr(host_pos + 6, host_end - host_pos - 6);
                std::cout << "   🌐 HTTP Host: " << host << std::endl;
                
                // Также ищем URL
                if (data.find("GET ") == 0) {
                    size_t url_start = data.find(' ') + 1;
                    size_t url_end = data.find(' ', url_start);
                    if (url_end != std::string::npos) {
                        std::string url = data.substr(url_start, url_end - url_start);
                        std::cout << "   🔗 URL: " << url << std::endl;
                    }
                }
            }
        }
    }
    
    bool is_valid_domain_start(unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }
    
    bool is_valid_domain_char(unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
               (c >= '0' && c <= '9') || c == '-' || c == '.';
    }
};

int main(int argc, char* argv[]) {
    int queue_num = 0;
    
    if (argc > 1) {
        queue_num = std::atoi(argv[1]);
    }
    
    if (geteuid() != 0) {
        std::cerr << "[-] Запускай с правами root! (sudo)" << std::endl;
        return 1;
    }
    
    NFQHandler handler(queue_num);
    
    if (!handler.init()) {
        return 1;
    }
    
    if (!handler.create_queue()) {
        return 1;
    }
    
    std::cout << "[+] NFQ детектор доменов запущен" << std::endl;
    std::cout << "[+] Номер очереди: " << queue_num << std::endl;
    std::cout << "[+] Ctrl+C для остановки\n" << std::endl;
    
    handler.start();
    
    return 0;
}