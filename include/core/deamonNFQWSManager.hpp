#pragma once

#include <iostream>

using namespace std;

class deamonNFQWSManager {
    public:
        deamonNFQWSManager();
        int startDeamon();
        int stopDeamon();
        int sendCommand(const string& command);
    private:
        pid_t daemon_pid;
};