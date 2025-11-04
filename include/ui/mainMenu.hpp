#pragma once
#include <iostream>
#include <vector>
#include <string>

using namespace std;

class mainMenu{
    public:
        void startMenu();
    private:
        string repeat(const string& s, int n);
        string paintMenu(vector<pair<int,string>> options, int highlight);

        //Обработчик команд
        vector<pair<int,string>> configCommandHandler(vector<pair<int,string>> option, int current_option);
};