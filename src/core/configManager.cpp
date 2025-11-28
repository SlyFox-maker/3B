#include "core/configManager.hpp"
#include "core/config.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

using namespace std;
using namespace config3B;
void configManager::saveConfigs(vector<pair<int,string>> options, int flag){
    /*
    100 - save nfqws main config
    */

    //Сохраняем конфиг nfqws main
    if(flag == 100){
        ofstream confOut(DPI_CONFIG_NFQWS_MAIN);
        int index=0;
        for(auto &opt : options)
        {
            if(opt.first == -5)
                confOut << index << "=" << opt.first << "\n";
            index++;
        }
        confOut.close();
        return;
    }
};
void configManager::loadConfigs(vector<pair<int,string>> &options, int flag){
    if (flag != 100)
        return;

    ifstream confIn(DPI_CONFIG_NFQWS_MAIN);
    if (!confIn.is_open()) {
        // Файл не открылся — просто выходим спокойно
        return;
    }

    string line;
    while (getline(confIn, line))
    {
        // Если строка пустая — пропускаем
        if (line.empty())
            continue;

        size_t delimPos = line.find('=');
        if (delimPos == string::npos)
            continue;

        string left  = line.substr(0, delimPos);
        string right = line.substr(delimPos + 1);

        // Если одна из частей пустая → пропускаем
        if (left.empty() || right.empty())
            continue;

        int index, value;

        // stoi может бросить исключение → аккуратно ловим
        try {
            index = stoi(left);
            value = stoi(right);
        } catch (...) {
            continue; // мусор нашли — пропускаем строку
        }

        // Проверяем границы вектора
        if (index < 0 || index >= (int)options.size())
            continue;

        // Итог: меняем второй элемент pair
        options[index].first = value;
    }

    confIn.close();
}
