#include "attackManager.hpp"
#include "ddaAttack.hpp"
#include "attackBase.hpp"
#include "configParser.hpp"

#include <iostream>
#include <unordered_map>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>

using namespace std;

void AttackManager::register_attack(const string& name, shared_ptr<AttackBase> attack) {
    AttackManager::attacks_[name] = attack;
    cout << "[+] Registered attack: " << name << endl;
}

bool AttackManager::initialize_all() {
    if (!config_parser_->load_configs()) {
        cerr << "[-] Failed to load configs\n";
        return false;
    }
        
        // Инициализируем все зарегистрированные атаки
    for (auto& [name, attack] : AttackManager::attacks_) {
        if (!attack->initialize()) {
            cerr << "[-] Failed to initialize attack: " << name << endl;
            return false;
        }
    }
        
    // Применяем конфигурацию
    apply_configuration();
        
    // Запускаем мониторинг конфигов
    start_config_checker();
        
    return true;
}
void AttackManager::process_packet(unsigned char* packet_data, int len, uint32_t id) {
    // Быстрая проверка - применяем только включенные атаки
    int enabled_count = 0;
    
    for (auto& [name, attack] : attacks_) {
        if (attack->is_enabled()) {
            enabled_count++;
            cout << "Applying attack: " << name << " to packet #" << id << endl;
            attack->process_packet(packet_data, len, id);
        }
    }
    
    if (enabled_count == 0) {
        cout << " No enabled attacks for packet #" << id << endl;
    }
}
void AttackManager::list_attacks() {
    cout << "\nRegistered attacks:\n";
    for (auto& [name, attack] : AttackManager::attacks_) {
        cout << "  " << (attack->is_enabled() ? "✔" : "X") 
             << " " << name << endl;
    }
    config_parser_->print_configs();
}

void AttackManager::apply_configuration() {
    auto enabled_attacks = config_parser_->get_enabled_attacks();
    
    // Включаем/выключаем атаки согласно конфигу
    for (auto& [name, attack] : attacks_) {
        bool should_enable = std::find(enabled_attacks.begin(), enabled_attacks.end(), name) != enabled_attacks.end();
        
        std::cout << "[🔧] " << name << " | Config enabled: " << should_enable 
                  << " | Current enabled: " << attack->is_enabled() << std::endl;
        
        if (should_enable && !attack->is_enabled()) {
            attack->enable();
            std::cout << "[!] ENABLED attack: " << name << std::endl;
        } else if (!should_enable && attack->is_enabled()) {
            attack->disable();
            std::cout << "[X] DISABLED attack: " << name << std::endl;
        }
    }
}
void AttackManager::start_config_checker() {
    running_ = true;
    config_checker_thread_ = std::thread([this]() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::seconds(config_check_interval_));
            
            if (config_parser_->has_changed()) {
                std::cout << "[!] Configuration changed, reloading...\n";
                config_parser_->load_configs();
                apply_configuration();
            }
        }
    });
}
void AttackManager::stop_config_checker() {
    running_ = false;
    if (config_checker_thread_.joinable()) {
        config_checker_thread_.join();
    }
}