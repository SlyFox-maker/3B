#include <core/deamonNFQWSManager.hpp>
#include <core/config.hpp>

#include <iostream>
#include <sys/wait.h>
#include <filesystem>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


using namespace std;
using namespace config3B;

deamonNFQWSManager::deamonNFQWSManager() : daemon_pid(-1) {}

int deamonNFQWSManager::startDeamon() {
    daemon_pid = fork();
    if (daemon_pid == 0) {
        // Child process
        char exe_path[1024];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1) {
            exe_path[len] = '\0';
            std::filesystem::path daemon_path = std::filesystem::path(exe_path).parent_path() / "nfqwsDeamon";
            execl(daemon_path.c_str(), "nfqwsDeamon", nullptr);
            perror("Failed to start daemon (path-based)");
        } else {
            perror("Failed to resolve /proc/self/exe");
        }

        // fallback — если всё выше не сработало
        execl("./nfqwsDeamon", "nfqwsDeamon", nullptr);
        perror("Failed to start daemon (fallback)");
        exit(1);
    }

    if (daemon_pid < 0) {
        cerr << "[-] Failed to fork daemon process." << endl;
        return -1;
    }

    cout << "[+] Daemon started with PID " << daemon_pid << endl;
    return 0;
}  

int deamonNFQWSManager::stopDeamon() {
    if (daemon_pid > 0) {
        kill(daemon_pid, SIGTERM);
        waitpid(daemon_pid, nullptr, 0);
        cout << "[+] Daemon with PID " << daemon_pid << " stopped." << endl;
        daemon_pid = -1;
        return 0;
    } else {
        cerr << "[-] Daemon is not running." << endl;
        return -1;
    }
}
int deamonNFQWSManager::sendCommand(const string& command) {
    int client_fd;
    struct sockaddr_un address;
    char buffer[256];

    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
        cerr << "[-] Socket creation failed." << endl;
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, DAEMON_SOCKET_PATH, sizeof(address.sun_path) - 1);

    if (connect(client_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "[-] Connection to daemon failed." << endl;
        close(client_fd);
        return -1;
    }

    send(client_fd, command.c_str(), command.size(), 0);
    memset(buffer, 0, sizeof(buffer));
    read(client_fd, buffer, sizeof(buffer) - 1);
    cout << "[+] Daemon response: " << buffer << endl;

    close(client_fd);
    return 0;
}