#include "configParser.hpp"
#include "core/config.hpp"


#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <sys/stat.h> 
#include <ctime>      
using namespace std;
using namespace config3B;


bool ConfigParser::load_configs() {
    if (!parse_attack_configs() || !parse_main_config()) {
        return false;
    }
    update_last_modified();
    return true;
}
bool ConfigParser::has_changed() {
    time_t current_main_mtime = get_file_mtime(main_config_path_);
    time_t current_attack_mtime = get_file_mtime(attack_configs_path_);
        
    return current_main_mtime > last_modified_ || current_attack_mtime > last_modified_;
}
void ConfigParser::reload_if_needed() {
    if (has_changed()) {
        cout << "[!] Config files changed, reloading...\n";
        load_configs();
    }
}
vector<string> ConfigParser::get_enabled_attacks() {
    std::vector<std::string> enabled;
    reload_if_needed();
    
    std::cout << "[📊] Attack statuses:\n";
    for (const auto& [attack_name, status] : attack_status_) {
        // Твоя специфическая логика
        bool is_enabled = (status == -5); // Только -5 означает включено
        std::cout << "  " << attack_name << " -> status: " << status 
                  << " (enabled: " << (is_enabled ? "YES" : "NO") << ")\n";
        
        if (is_enabled) {
            enabled.push_back(attack_name);
        }
    }
    return enabled;
}

const unordered_map<string, string>& ConfigParser::get_attack_params(const string& attack_name) {
    static unordered_map<string, string> empty;
    auto it = attack_configs_.find(attack_name);
    return (it != attack_configs_.end()) ? it->second : empty;
}

void ConfigParser::print_configs() {
    cout << "\n Current attack configuration:\n";
    for (const auto& [attack_name, status] : attack_status_) {
        cout << "  " << attack_name << " -> status: " << status;
        auto params = get_attack_params(attack_name);
        if (!params.empty()) {
            cout << " [";
            for (const auto& [key, value] : params) {
                cout << key << "=" << value << " ";
            }
            cout << "]";
        }
        cout << endl;
    }
}

bool ConfigParser::parse_attack_configs() {
    ifstream file(attack_configs_path_);
    if (!file.is_open()) {
        cerr << "[-] Cannot open attack config: " << attack_configs_path_ << std::endl;
        return false;
    }
        
    attack_configs_.clear();
    string line, current_section;
        
    while (getline(file, line)) {
        trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.size() - 2);
            cout << "[+] Found attack section: " << current_section << endl;
        } else {
            size_t delimiter = line.find('=');
            if (delimiter != string::npos) {
                string key = line.substr(0, delimiter);
                string value = line.substr(delimiter + 1);
                trim(key); trim(value);
                    
                attack_configs_[current_section][key] = value;
            }
        }
    }
    return true;
}

bool ConfigParser::parse_main_config() {
    ifstream file(main_config_path_);
    if (!file.is_open()) {
        cerr << "[-] Cannot open main config: " << main_config_path_ << endl;
            return false;
    }
        
    main_config_.clear();
    attack_status_.clear();
    string line;
        
    while (getline(file, line)) {
        trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
            
        size_t delimiter = line.find('=');
        if (delimiter != string::npos) {
            string index_str = line.substr(0, delimiter);
            string status_str = line.substr(delimiter + 1);
            trim(index_str); trim(status_str);
                
            try {
                int index = stoi(index_str);
                int status = stoi(status_str);
                    
                    // Находим атаку по индексу
                string attack_name = find_attack_by_index(index);
                if (!attack_name.empty()) {
                    main_config_[index] = attack_name;
                    attack_status_[attack_name] = status;
                    cout << "[+] Attack " << attack_name << " status: " << status << endl;
                }
            } catch (const exception& e) {
                cerr << "[-] Error parsing line: " << line << " - " << e.what() << endl;
            }
        }
    }
    return true;
}

string ConfigParser::find_attack_by_index(int index) {
    for (const auto& [attack_name, params] : attack_configs_) {
        auto it = params.find("index");
        if (it != params.end() && std::stoi(it->second) == index) {
            return attack_name;
        }
    }
    return "";
}

time_t ConfigParser::get_file_mtime(string& path) {
    struct stat result;
    if (stat(path.c_str(), &result) == 0) {
        return result.st_mtime;
    }
    return 0;
}

void ConfigParser::update_last_modified() {
    last_modified_ = std::max(
        get_file_mtime(main_config_path_),
        get_file_mtime(attack_configs_path_)
    );
}

void ConfigParser::trim(string& str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), str.end());
}