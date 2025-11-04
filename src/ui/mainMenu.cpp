#include "ui/mainMenu.hpp"
#include "core/configManager.hpp"

#include <iostream>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <termios.h>
#include <unistd.h>
#include <utility>
#include <fstream>
#include <array>
#include <map>

using namespace std;
using namespace std::chrono_literals;

// Цвета ANSI
const string RESET = "\033[0m";
const string CYAN  = "\033[36m";
const string PINK  = "\033[38;2;255;105;180m";
const string GRAY  = "\033[90m";
const string YELLOW= "\033[33m";
const string BOLD  = "\033[1m";

//Менюшки
/*
    -1 - action
    -2 - folder
    -3 - title

    100 - main menu
    200 - config menu
*/
//Будет один большой массив делаться уже при запуске, который будет сразу нумерировать последовательно 
//Как тут все списочки, и после по ним будем переходить
const vector<pair<int,string>> options = {
    {-3, "3B MENU"},
    {-2,"Configuration"},
    {-2,"Test of connection"},
    {-1, "Exit"}
};

const vector<pair<int,string>> configOptions_1 = {
    {-3, "Configuration Menu"},
    {-2,"nfqws"},
    {-2,"tpws"},
    {-2, "Back"}
};

const vector<pair<int,string>> configOptions_2 = {
    {-3, "nfqws Configuration"},
    {-2, "DPI desynchronization attack"},
    {-2, "Fakes"},
    {-2, "Modifications of fakes"},
    {-2, "Overlapping SEQUENCE NUMBERS"},
    {-2, "Assignment of IP_ID"},
    {-2, "Specific IPV6 modes"},
    {-2, "Modification of the original"},
    {-2, "Duplicates"},
    {-2, "Combining desynchronization methods"},
    {-2, "IP cache"},
    {-2, "DPI response to server reply"},
    {-2, "Synack mode(Router only)"},
    {-2, "Syndata mode"},
    {-2, "CONNTRACK"},
    {-2, "Reassembly"},
    {-2, "UDP support"},
    {-2, "IP fragmentation(old)"},
    {-2, "Multiple strategies"},
    {-2, "Filtering by wifi(No server)"},
    {-2, "Iptables for nfqws"},
    {-2, "Nftables для nfqws"},
    {-2, "Flow offloading"},
    {-1, "Back"}
};



map<int, vector<pair<int, string>>> allMenus = {
    {100, options},
    {200, configOptions_1},
    {210, configOptions_2}
};
// helper для повторения строки
string mainMenu::repeat(const string& s, int n) {
    string out;
    for (int i = 0; i < n; ++i) out += s;
    return out;
}

string mainMenu::paintMenu(vector<pair<int,string>> options, int highlight){
    // Получаем титульник (первый элемент)
    string title = options[0].second;

    // Вычисляем максимальную длину всех строк
    int maxLen = title.size();
    for(auto &l : options) {
        if((int)l.second.size() > maxLen)
            maxLen = l.second.size();
    }

    int padding = 15; // запас по бокам
    int width = maxLen + padding;

    string menu;
    menu += GRAY + "╔" + mainMenu::repeat("═", width) + "╗\n";

    // Центрируем титульник
    int leftPad = (width - title.size()) / 2;
    int rightPad = width - title.size() - leftPad;
    menu += GRAY + "║" + RESET + CYAN + BOLD +
            string(leftPad, ' ') + title + string(rightPad, ' ') +
            RESET + GRAY + "║\n";
    menu += GRAY + "╠" + mainMenu::repeat("═", width) + "╣" + RESET + "\n";

    // Отрисовка пунктов
    for (int i = 1; i < (int)options.size(); ++i) { // с 1, потому что 0 — это титульник
        string line;

        if(options[i].first == -1 || options[i].first == -2)
            line = options[i].second;
        else
            line = "[" + string(options[i].first == 1 ? "*" : " ") + "] " + options[i].second;

        // Подсветка активного пункта
        if (i == highlight)
            menu += GRAY + "║ " + YELLOW + BOLD + "> " + line + RESET +
                    string(max(0, width - (int)line.size() - 3), ' ') + GRAY + "║\n";
        else
            menu += GRAY + "║   " + PINK + line + RESET +
                    string(max(0, width - (int)line.size() - 3), ' ') + GRAY + "║\n";
    }

    menu += GRAY + "╚" + mainMenu::repeat("═", width) + "╝" + RESET + "\n";
    return menu;
}

vector<pair<int,string>> mainMenu::configCommandHandler(vector<pair<int,string>> option, int current_option){
    if(option[current_option].second == "nfqws"){
        return allMenus[210];
    }
    return option;
}




int roundDown(int num) {
    if (num == 200)
        return 100;

    // обычное округление вниз до ближайших 10
    return (num / 10) * 10;
}


void mainMenu::startMenu(){
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO); // raw mode
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt);

    system("clear");
    cout << CYAN << "App is running..." << RESET << endl;
    this_thread::sleep_for(800ms);
    system("clear");

    //Loading of configs
            
            

    //Show main menu


    int highlight = 0;
    int current_option = -1;
    int current_menu = 100;

    vector<pair<int,string>> options = allMenus[current_menu];
    while (true) {
        system("clear");
        cout << mainMenu::paintMenu(options, highlight);

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        current_option = highlight;
        if(c == '\033'){
            char seq[2];
            if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
            if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;

            if (seq[0] == '[') {
                if (seq[1] == 'A') { // up
                    highlight = (highlight - 1 + options.size()) % options.size();
                } else if (seq[1] == 'B') { // down
                    highlight = (highlight + 1) % options.size();
                }
            }
            continue;
        }
        if(c == '\n'){
            // чекаем опцию
            if(current_menu>=100 && current_menu<200){
                if(options[current_option].second == "Exit")
                {
                    break;
                }
                else if (options[current_option].second =="Configuration")
                {
                    current_menu = 200;
                    options = allMenus[200];
                    highlight = 0;
                }
                else if (options[current_option].second =="Test of connection")
                {
                    /* code */
                }
            }
            else if(current_menu >= 200 && current_menu < 300){
                options = mainMenu::configCommandHandler(options, current_option);
            }
            else{
                if(options[current_option].first == -1) break;
                if(options[current_option].first == 1)
                    options[current_option].first=0;
                else
                    options[current_option].first=1;
            }

            if (options[current_option].second =="Back")
            {  
                
                current_menu =roundDown(current_menu);
                options = allMenus[current_menu];
                highlight = 0;
            }
        }
        system("clear");
    }

    cout << RESET << "Bye.\n";
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
}
