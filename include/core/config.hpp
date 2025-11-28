#pragma once
namespace config3B{
    //Сетевые конфиги для таблицы NAT и прокси
    constexpr int PORT_FROM = 443;   //Порт, который будет перенаправлять на наш прокси                                     
    constexpr int PORT_TO = 8443;    //Порт, на котором будем прокси и сюда же перенаправлять трафик

    //Кеш файлы
    constexpr char IP_FORWARD_BACKUP[] = "./cash/ip_forward_backup.txt";

    //Работа демона
    constexpr char DAEMON_SOCKET_PATH[] = "./cash/nfqws.sock";
    constexpr char DAEMON_SOCKET_MYDEAMON[] = "./cash/mydaemon.sock";

    //Файлы конфигураций
    constexpr char DPI_CONFIG_NFQWS_MAIN[] = "./configuration/nfqws/main.txt";

}                            