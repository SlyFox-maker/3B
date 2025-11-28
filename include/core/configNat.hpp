#pragma once
#include <iostream>

using namespace std;

class configNat {
    public:
        int startConfigNat(int queue_num = 0);
        int stopConfigNat(int queue_num = 0);
    private:
        bool save_ip_forward_value();
        bool restore_ip_forward_value();
        bool get_ip_forward();
        bool set_ip_forward(bool enable);
        static int run_command(const string &cmd);
        bool add_redirect_rule(int from_port, int to_port);
        bool iptables_rule_exists(int from_port, int to_port);
        bool remove_redirect_rule(int from_port, int to_port);

        // Новые методы (для nfqws)
        static bool add_nfqueue_rule(int port, int queue_num = 0);
        static bool remove_nfqueue_rule(int port, int queue_num = 0);
        static bool add_nfqueue_output_rule(int port, int queue_num = 0);
        static bool remove_nfqueue_output_rule(int port, int queue_num = 0);
        
        // Утилиты для проверки существования правил
        static bool nfqueue_rule_exists(int port, int queue_num = 0);
        static bool nfqueue_output_rule_exists(int port, int queue_num = 0);
};