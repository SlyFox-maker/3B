#pragma once
#include <iostream>
#include <vector>
#include <string>

using namespace std;

class configManager{
    public:
        static void loadConfigs(vector<pair<int,string>>& options,int flag);
        static void saveConfigs(vector<pair<int,string>> options, int flag);
};