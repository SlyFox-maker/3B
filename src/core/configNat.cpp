#include <core/configNat.hpp>
#include "core/config.hpp"

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <array>
#include <memory>
#include <cstdio>
#include <sys/wait.h>

using namespace std;
using namespace config3B;

int from_port = PORT_FROM;
int to_port = PORT_TO;

bool configNat::get_ip_forward() {
    const char *path = "/proc/sys/net/ipv4/ip_forward";
    ifstream f(path);
    if (!f.is_open()) return false;
    int val = 0;
    f >> val;
    return val != 0;
}

const char *rollback_file = IP_FORWARD_BACKUP;
bool configNat::save_ip_forward_value() {
    bool val = get_ip_forward();
    ofstream f(rollback_file);
    if (!f.is_open()) return false;
    f << (val ? "1" : "0") << endl;
    return !f.fail();
}

bool configNat::restore_ip_forward_value() {
    ifstream f(rollback_file);
    if (!f.is_open()) return false;
    int val;
    f >> val;
    set_ip_forward(val != 0);
    return true;
}

bool configNat::set_ip_forward(bool enable){
    const char *path = "/proc/sys/net/ipv4/ip_forward";
    ofstream f(path);
    if (!f.is_open()) {
        string cmd = string("sysctl -w net.ipv4.ip_forward=") + (enable ? "1" : "0");
        int rc = run_command(cmd);
        return rc == 0;
    }
    f << (enable ? "1" : "0") << endl;
    return !f.fail();
}

int configNat::run_command(const string &cmd) {
    int status = system(cmd.c_str());
    if (status == -1) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

bool configNat::iptables_rule_exists(int from_port, int to_port) {
    // Проверяем правило в PREROUTING
    string cmd1 = "iptables -t nat -C PREROUTING -p tcp --dport " + to_string(from_port)
                      + " -j REDIRECT --to-port " + to_string(to_port) + " 2>/dev/null";
    
    // Проверяем правило в OUTPUT (для localhost)
    string cmd2 = "iptables -t nat -C OUTPUT -p tcp --dport " + to_string(from_port)
                      + " -j REDIRECT --to-port " + to_string(to_port) + " 2>/dev/null";
    
    int rc1 = run_command(cmd1);
    int rc2 = run_command(cmd2);
    
    return (rc1 == 0 || rc2 == 0);
}

bool configNat::add_redirect_rule(int from_port, int to_port) {
    if (iptables_rule_exists(from_port, to_port)) {
        cout << "[+] The rule already exists: " << from_port << " -> " << to_port << "\n";
        return true;
    }
    
    // Правило для внешнего трафика (PREROUTING)
    string cmd1 = "iptables -t nat -A PREROUTING -p tcp --dport " + to_string(from_port)
                      + " -j REDIRECT --to-port " + to_string(to_port);
    
    // Правило для локального трафика (OUTPUT)
    string cmd2 = "iptables -t nat -A OUTPUT -p tcp --dport " + to_string(from_port)
                      + " -j REDIRECT --to-port " + to_string(to_port);
    
    int rc1 = run_command(cmd1);
    int rc2 = run_command(cmd2);
    
    if (rc1 == 0 && rc2 == 0) {
        cout << "[+] Rules added: " << from_port << " -> " << to_port << "\n";
        cout << "[+] PREROUTING (external traffic) and OUTPUT (localhost) are configured\n";
        return true;
    } else {
        cerr << "[-] Failed to add rules (PREROUTING: " << rc1 << ", OUTPUT: " << rc2 << ")\n";
        return false;
    }
}

bool configNat::remove_redirect_rule(int from_port, int to_port) {
    bool anyRemoved = false;
    
    // Удаляем из PREROUTING
    while (true) {
        string cmd1 = "iptables -t nat -D PREROUTING -p tcp --dport " + to_string(from_port)
                          + " -j REDIRECT --to-port " + to_string(to_port) + " 2>/dev/null";
        int rc1 = run_command(cmd1);
        if (rc1 == 0) {
            anyRemoved = true;
            continue;
        } else {
            break;
        }
    }
    
    // Удаляем из OUTPUT
    while (true) {
        string cmd2 = "iptables -t nat -D OUTPUT -p tcp --dport " + to_string(from_port)
                          + " -j REDIRECT --to-port " + to_string(to_port) + " 2>/dev/null";
        int rc2 = run_command(cmd2);
        if (rc2 == 0) {
            anyRemoved = true;
            continue;
        } else {
            break;
        }
    }
    
    if (anyRemoved) {
        cout << "[+] All rules removed: " << from_port << " -> " << to_port << "\n";
        return true;
    } else {
        cerr << "[*] Nothing deleted — rules not found\n";
        return false;
    }
}
bool configNat::add_nfqueue_rule(int port, int queue_num) {
    if (nfqueue_rule_exists(port, queue_num)) {
        cout << "[+] NFQUEUE rule already exists: port " << port 
                  << " -> queue " << queue_num << " (FORWARD)" << endl;
        return true;
    }
    
    string cmd = "iptables -I FORWARD -p tcp --dport " + 
                     to_string(port) + " -j NFQUEUE --queue-num " + 
                     to_string(queue_num);
    
    int rc = run_command(cmd);
    if (rc == 0) {
        cout << "[+] Added NFQUEUE rule: port " << port 
                  << " -> queue " << queue_num << " (FORWARD)" << endl;
        return true;
    } else {
        cerr << "[-] Failed to add NFQUEUE rule (FORWARD): code " << rc << endl;
        return false;
    }
}

bool configNat::add_nfqueue_output_rule(int port, int queue_num) {
    if (nfqueue_output_rule_exists(port, queue_num)) {
        cout << "[+] NFQUEUE OUTPUT rule already exists: port " << port 
                  << " -> queue " << queue_num << endl;
        return true;
    }
    
    string cmd = "iptables -I OUTPUT -p tcp --dport " + 
                     to_string(port) + " -j NFQUEUE --queue-num " + 
                     to_string(queue_num);
    
    int rc = run_command(cmd);
    if (rc == 0) {
        cout << "[+] Added NFQUEUE rule: port " << port 
                  << " -> queue " << queue_num << " (OUTPUT)" << endl;
        return true;
    } else {
        cerr << "[-] Failed to add NFQUEUE rule (OUTPUT): code " << rc << endl;
        return false;
    }
}

bool configNat::remove_nfqueue_rule(int port, int queue_num) {
    bool removed = false;
    
    // Пытаемся удалить все вхождения правила
    while (true) {
        string cmd = "iptables -D FORWARD -p tcp --dport " + 
                         to_string(port) + " -j NFQUEUE --queue-num " + 
                         to_string(queue_num) + " 2>/dev/null";
        
        int rc = run_command(cmd);
        if (rc == 0) {
            removed = true;
            continue; // Продолжаем пока есть правила для удаления
        } else {
            break;
        }
    }
    
    if (removed) {
        cout << "[+] Removed NFQUEUE rules: port " << port 
                  << " -> queue " << queue_num << " (FORWARD)" << endl;
    } else {
        cout << "[*] NFQUEUE rules not found for deletion (FORWARD)" << endl;
    }
    
    return removed;
}

bool configNat::remove_nfqueue_output_rule(int port, int queue_num) {
    bool removed = false;
    
    while (true) {
        string cmd = "iptables -D OUTPUT -p tcp --dport " + 
                         to_string(port) + " -j NFQUEUE --queue-num " + 
                         to_string(queue_num) + " 2>/dev/null";
        
        int rc = run_command(cmd);
        if (rc == 0) {
            removed = true;
            continue;
        } else {
            break;
        }
    }
    
    if (removed) {
        cout << "[+] Removed NFQUEUE rules: port " << port 
                  << " -> queue " << queue_num << " (OUTPUT)" << endl;
    } else {
        cout << "[*] NFQUEUE rules not found for deletion (OUTPUT)" << endl;
    }
    
    return removed;
}

bool configNat::nfqueue_rule_exists(int port, int queue_num) {
    string cmd = "iptables -C FORWARD -p tcp --dport " + 
                     to_string(port) + " -j NFQUEUE --queue-num " + 
                     to_string(queue_num) + " 2>/dev/null";
    return run_command(cmd) == 0;
}

bool configNat::nfqueue_output_rule_exists(int port, int queue_num) {
    string cmd = "iptables -C OUTPUT -p tcp --dport " + 
                     to_string(port) + " -j NFQUEUE --queue-num " + 
                     to_string(queue_num) + " 2>/dev/null";
    return run_command(cmd) == 0;
}

int configNat::startConfigNat(int queue_num) {
    cout << "NAT configuration started." << endl;

    // Сохраняем текущее значение ip_forward (для обоих режимов)
    if (!save_ip_forward_value()) {
        cerr << "[-] Failed to save the current value of ip_forward\n";
    }
    
    // Включаем ip_forward (нужно для обоих режимов)
    if (!set_ip_forward(true)) {
        cerr << "[-] Failed to enable ip_forward (root privileges required?)\n";
        return 2;
    }

    // РЕЖИМ NFQWS - новый функционал
        if (!add_nfqueue_rule(from_port, queue_num)) {
            cerr << "[-] Failed to add NFQUEUE rule (FORWARD)\n";
            return 4;
        }
        if (!add_nfqueue_output_rule(from_port, queue_num)) {
            cerr << "[-] Failed to add NFQUEUE rule (OUTPUT)\n";
            // Откатываем FORWARD правило если OUTPUT не добавилось
            remove_nfqueue_rule(from_port, queue_num);
            return 5;
        }
        cout << "[*] NFQUEUE enabled for port " << from_port 
                  << " (queue " << queue_num << ")\n";

    return 0;
}

int configNat::stopConfigNat(int queue_num) {
    cout << "Stopping NAT configuration" << endl;

    remove_nfqueue_rule(from_port, queue_num);
    remove_nfqueue_output_rule(from_port, queue_num);

    // Восстанавливаем исходное значение ip_forward (для обоих режимов)
    if (!restore_ip_forward_value()) {
        cerr << "[-] Failed to restore ip_forward value\n";
        return 1;
    }
    
    cout << "[*] Configuration stopped\n";
    return 0;
}