#pragma once
#include <iostream>
#include <vector>
#include <string>

using namespace std;

class configManager{
    public:
        void loadConfigs();
        void saveConfigs(vector<pair<int,string>> options);
};