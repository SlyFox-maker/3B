#include "core/configManager.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <fstream>

using namespace std;

void configManager::saveConfigs(vector<pair<int,string>> options){
    ofstream confOut("config.cfg");
    for(auto &opt : options)
    {
        confOut << opt.second << "=" << opt.first << "\n";
    }
    confOut.close();
};
void configManager::loadConfigs(){

};