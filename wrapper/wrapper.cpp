#include <microhttpd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <signal.h>
#include <unistd.h>
#include <pty.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string>
#include <iostream>
#include <thread>
#include <atomic>

#define PORT 8080
#define SERVICE_COMMAND "/evemu/deploy/server/eve-server"
#define RESTART_SIGNAL SIGUSR1

int master_fd;
pid_t service_pid;
std::atomic<bool> server_running(true);

MHD_Result send_response(struct MHD_Connection *connection, const char *page) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(page), (void*)page, MHD_RESPMEM_PERSISTENT);
    if (!response) return MHD_NO;

    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

void restart_service() {
    kill(service_pid, SIGTERM);
    sleep(5);
    kill(service_pid, SIGTERM);
    sleep(5);
    kill(service_pid, SIGKILL);
    kill(service_pid, SIGKILL);

    service_pid = forkpty(&master_fd, nullptr, nullptr, nullptr);
    if (service_pid == 0) {
        execlp(SERVICE_COMMAND, SERVICE_COMMAND, nullptr);
        perror("execlp");
        exit(EXIT_FAILURE);
    }
}

void restart_all() {
    kill(service_pid, SIGTERM);
    sleep(5);
    kill(service_pid, SIGTERM);
    sleep(5);
    kill(service_pid, SIGKILL);
    kill(service_pid, SIGKILL);
    sleep(3);
    kill(getpid(), RESTART_SIGNAL);
}

inline std::string GetDateTime()
{
    time_t now = time(0);
    struct tm  tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
    return buf;
}

MHD_Result handle_probe(struct MHD_Connection *connection) {
    std::cout << GetDateTime() << "[Wrapper] Probe issued.\n";
    std::string result;
    char buffer[256];

    // 发送测试服务状态的命令
    write(master_fd, "s\n", 2);

    // 设置非阻塞读取
    fd_set rfds;
    struct timeval tv;
    int retval;
    bool data_ready = false;

    FD_ZERO(&rfds);
    FD_SET(master_fd, &rfds);

    tv.tv_sec = 5;  // 等待5秒
    tv.tv_usec = 0;

    do {
        retval = select(master_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
            return MHD_NO;
        }
        if (retval) {
            ssize_t count = read(master_fd, buffer, sizeof(buffer) - 1);
            if (count > 0) {
                buffer[count] = '\0';
                result += buffer;
                if (result.find("VM") != std::string::npos ||
                    result.find("Client") != std::string::npos ||
                    result.find("Normal") != std::string::npos ||
                    result.find("Command") != std::string::npos) {
                    data_ready = true;
                    break;
                }
            }
        } else {
            // 超时
            break;
        }
    } while (true);

    std::cout << GetDateTime() << "[Wrapper] Probe result " << result;
    if (data_ready) return send_response(connection, "true");

    restart_service();
    return send_response(connection, "false");
}

MHD_Result handle_execute(struct MHD_Connection *connection, const char *cmd) {
    std::cout << GetDateTime() << "[Wrapper] Executing " << cmd << " .\n";
    std::string result;
    char buffer[256];

    std::string command = std::string(cmd) + "\n";
    write(master_fd, command.c_str(), command.length());

    // 设置非阻塞读取
    fd_set rfds;
    struct timeval tv;
    int retval;
    bool data_ready = false;

    FD_ZERO(&rfds);
    FD_SET(master_fd, &rfds);

    tv.tv_sec = 5;  // 等待5秒
    tv.tv_usec = 0;

    do {
        retval = select(master_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
            return MHD_NO;
        }
        if (retval) {
            ssize_t count = read(master_fd, buffer, sizeof(buffer) - 1);
            if (count > 0) {
                buffer[count] = '\0';
                result += buffer;
                break;
            }
        } else {
            // 超时
            break;
        }
    } while (true);

    if (result.empty()) result = "blank";
    return send_response(connection, result.c_str());
}

MHD_Result handle_restart(struct MHD_Connection *connection) {
    std::cout << GetDateTime() << "[Wrapper] Service restart issued.\n";
    restart_service();
    return send_response(connection, "Server restarting...");
}

MHD_Result handle_restart_all(struct MHD_Connection *connection) {
    std::cout << GetDateTime() << "[Wrapper] Wrapper and service restart issued.\n";
    restart_all();
    return send_response(connection, "Wrapper and service restarting...");
}

MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                        const char *url, const char *method, const char *version,
                        const char *upload_data, size_t *upload_data_size, void **con_cls) {
    std::cout << GetDateTime() << "[Wrapper] Client " << url << "\n";
    if (strcmp(method, "GET") != 0) return MHD_NO;

    if (strcmp(url, "/api") != 0) return send_response(connection, "Bad request.");
    const char *action = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "action");
    if (!action) return send_response(connection, "Bad request.");

    if (strcmp(action, "probe") == 0) return handle_probe(connection);
    if (strcmp(action, "execute") == 0) {
        const char *cmd = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "cmd");
        if (!cmd) return send_response(connection, "Bad request.");
        return handle_execute(connection, cmd);
    }
    if (strcmp(action, "restart") == 0) return handle_restart(connection);
    if (strcmp(action, "restartall") == 0) return handle_restart_all(connection);

    return send_response(connection, "Bad request.");
}

void handle_signal(int sig) {
    if (sig == RESTART_SIGNAL) {
        // 重启自身
        execl("/evemu/deploy/server/wrapper", "/evemu/deploy/server/wrapper", nullptr);
        perror("execl");
        exit(EXIT_FAILURE);
    }
}

void monitor_input() {
    std::string input;
    while (server_running) {
        printf("> ");
        std::getline(std::cin, input);
        if (input == "restart") {
            printf("Issue 'restart confirm' to confirm the wrapper restart.\n");
	    continue;
        }
        if (input == "restart confirm") {
            restart_all();
            continue;
        }
        if (input == "stop server") {
            server_running = false;
            continue;
        }
        if (input == "bootstrap") {
            restart_all();
	    continue;
        }
        input += "\n";
        write(master_fd, input.c_str(), input.length());
    }
}

void monitor_output() {
    char buffer[256];
    while (server_running) {
        ssize_t count = read(master_fd, buffer, sizeof(buffer) - 1);
        if (count <= 0) continue;
        buffer[count] = '\0';
        std::cout << buffer;
        std::cout.flush();
    }
}

int main() {
    signal(RESTART_SIGNAL, handle_signal);

    // initiate eve-server
    service_pid = forkpty(&master_fd, nullptr, nullptr, nullptr);
    if (service_pid == 0) {
        execlp(SERVICE_COMMAND, SERVICE_COMMAND, nullptr);
        perror("execlp");
        exit(EXIT_FAILURE);
    }
    // bootstrap wrapper
    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, PORT, nullptr, nullptr,
                                                 &answer_to_connection, nullptr, MHD_OPTION_END);
    if (!daemon) return 1;
    // handle console i/o
    std::thread input_thread(monitor_input);
    std::thread output_thread(monitor_output);

    printf("Server running on port %d\n", PORT);

    while (server_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    // kill on stop
    MHD_stop_daemon(daemon);

    kill(service_pid, SIGKILL);

    input_thread.join();
    output_thread.join();

    return 0;
}
