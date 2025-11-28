#include "attackBase.hpp"

#include <string>
#include <unordered_map>
#include <iostream>
#include <cstdint>

using namespace std;

void AttackBase::apply_parameters(const unordered_map<string, string>& params) {
    cout << "[!] Applying parameters for " << name_ << ":\n";
    for (const auto& [key, value] : params) {
        cout << "    " << key << " = " << value << endl;
    }
}

void AttackBase::enable() {
    enabled_ = true;
}
void AttackBase::disable() {
    enabled_ = false;
}