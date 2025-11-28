#pragma once
#include <string>
#include <unordered_map>
#include <iostream>
#include <cstdint>

using namespace std;

class AttackBase{
    protected:
        bool enabled_ = false;
        string name_;

    public:
        AttackBase(const string& name) : name_(name) {}
        virtual ~AttackBase() = default;

        virtual bool initialize() = 0;
        virtual void process_packet(unsigned char* packet_data, int len, uint32_t id) = 0;
        virtual void cleanup() = 0;

        virtual void apply_parameters(const unordered_map<string, string>& params);
        void enable();
        void disable();
        bool is_enabled() const { return enabled_; }
        string get_name() const { return name_; }
};