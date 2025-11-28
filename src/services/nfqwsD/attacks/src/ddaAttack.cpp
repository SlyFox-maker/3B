#include "ddaAttack.hpp"
#include <unordered_map>
#include <iostream>
#include <cstdint>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

bool DDAAttack::initialize() {
    cout << "[+] DDA attack initialized\n";
    return true;
}

void DDAAttack::process_packet(unsigned char* packet_data, int len, uint32_t id) {
    if (!enabled_) return;
    
    cout << "DDA АТАКА СРАБОТАЛА для пакета #" << id << "!" << endl;
    
    // Простая проверка - выводим информацию о пакете
    struct iphdr* ip_header = (struct iphdr*)packet_data;
    if (ip_header->protocol == IPPROTO_TCP) {
        int ip_header_len = ip_header->ihl * 4;
        struct tcphdr* tcp_header = (struct tcphdr*)(packet_data + ip_header_len);
        uint16_t dst_port = ntohs(tcp_header->dest);
        
        cout << "   Порт назначения: " << dst_port << endl;
    }
}

void DDAAttack::apply_parameters(const unordered_map<string, string>& params) {
    AttackBase::apply_parameters(params);
        
    for (const auto& [key, value] : params) {
        if (key == "fragment_size") {
            fragment_size_ = stoi(value);
        } else if (key == "delay_ms") {
            delay_ms_ = stoi(value);
        } else if (key == "probability") {
            probability_ = stof(value);
        }
    }
        
    cout << "[!] DDA parameters applied: fragment_size=" << fragment_size_
              << ", delay_ms=" << delay_ms_ << ", probability=" << probability_ << endl;
}

void DDAAttack::cleanup() {
    cout << "[-] DDA attack cleaned up\n";
}