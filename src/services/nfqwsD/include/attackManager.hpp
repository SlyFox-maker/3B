#pragma once

#include "attackBase.hpp"
#include "configParser.hpp"

#include <iostream>
#include <unordered_map>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>

using namespace std;

class AttackManager {
    public:
        AttackManager(const string& main_config_path, const string& attack_configs_path) {
            config_parser_ = make_unique<ConfigParser>(main_config_path, attack_configs_path);
        }
        ~AttackManager() {
            stop_config_checker();
        }
        void register_attack(const string& name, shared_ptr<AttackBase> attack);
        bool initialize_all();
        void process_packet(unsigned char* packet_data, int len, uint32_t id);
        void list_attacks();


    private:
        unordered_map<string, shared_ptr<AttackBase>> attacks_;
        unique_ptr<ConfigParser> config_parser_;
        thread config_checker_thread_;
        bool running_ = false;
        int config_check_interval_ = 60; // секунды

        void apply_configuration();
        void start_config_checker();
        void stop_config_checker();
};
