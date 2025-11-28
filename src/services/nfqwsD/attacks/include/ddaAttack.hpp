#pragma once
#include "attackBase.hpp"
#include <unordered_map>
#include <iostream>
#include <cstdint>

using namespace std;

class DDAAttack : public AttackBase {
    private:
        int fragment_size_ = 256;
        int delay_ms_ = 5;
        float probability_ = 0.3f;
    public:
        DDAAttack() : AttackBase("dda") {}
        bool initialize() override;
        void process_packet(unsigned char* packet_data, int len, uint32_t id) override;
        void apply_parameters(const unordered_map<string, string>& params) override;
        void cleanup() override;

};