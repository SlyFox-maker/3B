#pragma once

#include <string>
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
using namespace std;


class ConfigParser{
    public:
        ConfigParser(const std::string& main_path, const std::string& attack_path) 
        : main_config_path_(main_path), attack_configs_path_(attack_path) {}

        bool load_configs();
        bool has_changed();
        void reload_if_needed();
        vector<string> get_enabled_attacks();
        const unordered_map<string, string>& get_attack_params(const string& attack_name);
        void print_configs();
    private:
        unordered_map<string, unordered_map<string, string>> attack_configs_;
        unordered_map<int, string> main_config_; // index -> attack_name
        unordered_map<string, int> attack_status_; // attack_name -> status
        time_t last_modified_ = 0;
        string main_config_path_;
        string attack_configs_path_;

        bool parse_attack_configs();
        bool parse_main_config();
        string find_attack_by_index(int index);
        time_t get_file_mtime(string& path);
        void update_last_modified();
        void trim(string& str);
};