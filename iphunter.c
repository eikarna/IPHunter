#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>

#define MAX_TARGETS 1024
#define MAX_IP_LEN 64
#define MAX_IFACE_LEN 32
#define PID_FILE "/data/local/tmp/iphunter.pid"
#define LOG_FILE "/data/local/tmp/iphunter.log"
#define AIRPLANE_TOGGLE_DELAY 1
#define NETWORK_READY_TIMEOUT 60

volatile sig_atomic_t running = 1;
int daemon_mode = 0;
int delay = 5;
char *targets[MAX_TARGETS];
int target_count = 0;
FILE *logfp = NULL;

void log_message(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    if (daemon_mode) {
        if (!logfp) {
            va_end(args);
            return;
        }
        vfprintf(logfp, format, args);
        fflush(logfp);
    } else {
        vprintf(format, args);
        fflush(stdout);
    }
    
    va_end(args);
}

void toggle_airplane_mode(int on) {
    const char *state = on ? "1" : "0";
    const char *broadcast_state = on ? "true" : "false";
    
    char cmd1[47];
    snprintf(cmd1, sizeof(cmd1), "su -c \"settings put global airplane_mode_on %s\"", state);
    
    char cmd2[94];
    snprintf(cmd2, sizeof(cmd2), "su -c \"am broadcast -a android.intent.action.AIRPLANE_MODE --ez state %s > /dev/null 2>&1\"",
             broadcast_state);
    
    log_message("[*] %s Airplane Mode...\n", on ? "Enabling" : "Disabling");
    system(cmd1);
    system(cmd2);
}

int get_active_interface_and_ip(char *iface, size_t iface_len, char *ip, size_t ip_len) {
    FILE *fp = popen("ip -4 route ls 2>/dev/null | grep -v \"tun[0-9]\"", "r");
    if (!fp) {
        log_message("[-] popen failed: %s\n", strerror(errno));
        return -1;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *dev_ptr = strstr(line, "dev ");
        char *src_ptr = strstr(line, "src ");
        
        if (dev_ptr && src_ptr && src_ptr > dev_ptr) {
            dev_ptr += 4;
            char *dev_end = strchr(dev_ptr, ' ');
            size_t dev_len = dev_end - dev_ptr;
            
            if (dev_len > 0 && dev_len < iface_len) {
                strncpy(iface, dev_ptr, dev_len);
                iface[dev_len] = '\0';
                
                src_ptr += 4;
                char *src_end = strchr(src_ptr, ' ');
                size_t src_len = src_end - src_ptr;
                
                if (src_len > 0 && src_len < ip_len) {
                    strncpy(ip, src_ptr, src_len);
                    ip[src_len] = '\0';
                    found = 1;
                    break;
                }
            }
        }
    }

    pclose(fp);
    
    if (!found) {
        strncpy(iface, "N/A", iface_len);
        strncpy(ip, "N/A", ip_len);
        return -1;
    }
    return 0;
}

int is_target_ip(const char *ip, char **targets, int target_count) {
    if (target_count == 0 || !ip || strcmp(ip, "N/A") == 0) 
        return 0;

    regex_t regex;
    char pattern[128];

    for (int i = 0; i < target_count; i++) {
        snprintf(pattern, sizeof(pattern), "^%s", targets[i]);
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
            continue;
        }
        
        int ret = regexec(&regex, ip, 0, NULL, 0);
        regfree(&regex);
        
        if (ret == 0) {
            return 1;
        }
    }
    return 0;
}

int parse_targets(const char *str, char **targets, int *count) {
    if (!str || !*str) return -1;
    
    char *copy = strdup(str);
    if (!copy) return -1;

    char *token = strtok(copy, ";");
    *count = 0;

    while (token && *count < MAX_TARGETS) {
        // Trim whitespace
        while (isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace((unsigned char)*end)) end--;
        end[1] = '\0';

        if (*token) {
            targets[*count] = strdup(token);
            if (!targets[*count]) {
                free(copy);
                return -1;
            }
            (*count)++;
        }
        token = strtok(NULL, ";");
    }
    free(copy);
    return 0;
}

void handle_signal(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        running = 0;
    }
}

int write_pid_file() {
    FILE *pidfile = fopen(PID_FILE, "w");
    if (!pidfile) {
        log_message("[-] fopen failed: %s\n", strerror(errno));
        return -1;
    }
    fprintf(pidfile, "%d", getpid());
    fclose(pidfile);
    return 0;
}

void cleanup_resources() {
    for (int i = 0; i < target_count; i++) {
        free(targets[i]);
    }
    target_count = 0;
    
    if (daemon_mode) {
        unlink(PID_FILE);
    }
    
    if (logfp) {
        fclose(logfp);
        logfp = NULL;
    }
}

int daemonize() {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) return -1;

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Open log file
    logfp = fopen(LOG_FILE, "a");
    if (!logfp) {
        return -1;
    }

    if (write_pid_file() < 0) {
        fclose(logfp);
        logfp = NULL;
        return -1;
    }
    
    return 0;
}

void wait_for_network() {
    char iface[MAX_IFACE_LEN] = {0};
    char ip[MAX_IP_LEN] = {0};
    int timeout = 0;
    
    while (timeout < NETWORK_READY_TIMEOUT && running) {
        if (get_active_interface_and_ip(iface, sizeof(iface), ip, sizeof(ip)) == 0) {
            if (strcmp(ip, "N/A") != 0) {
                return;
            }
        }
        sleep(1);
        timeout++;
    }
    log_message("[-] Network timeout after %d seconds\n", NETWORK_READY_TIMEOUT);
}

void print_usage() {
    printf("Usage:\n");
    printf("  Normal mode: iphunter [delay] [targets]\n");
    printf("  Daemon mode: iphunter -d [delay] [targets]\n");
    printf("\nExamples:\n");
    printf("  iphunter 5 \"10.21.*;192.168.*\"\n");
    printf("  iphunter -d 15 \"10.2[1-3].*;192.168.[0-9]+\"\n");
}

int main(int argc, char *argv[]) {
    atexit(cleanup_resources);
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);

    // Parse arguments
    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
        if (argc > 2) delay = atoi(argv[2]);
        if (argc > 3) parse_targets(argv[3], targets, &target_count);
    } else if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage();
        return 0;
    } else {
        if (argc > 1) delay = atoi(argv[1]);
        if (argc > 2) parse_targets(argv[2], targets, &target_count);
    }

    if (daemon_mode) {
        if (daemonize() < 0) {
            fprintf(stderr, "[-] Daemonization failed\n");
            return EXIT_FAILURE;
        }
        log_message("[*] Daemon started (PID: %d)\n", getpid());
        log_message("[*] Targets:");
        for (int i = 0; i < target_count; i++) 
            log_message(" %s", targets[i]);
        log_message("\n[*] Check interval: %d seconds\n", delay);
    } else {
        printf("[*] Starting IP Hunter\n");
        printf("[*] Delay: %ds\n", delay);
        if (target_count > 0) {
            printf("[*] Targets:");
            for (int i = 0; i < target_count; i++) 
                printf(" %s", targets[i]);
            printf("\n");
        }
    }

    char last_ip[MAX_IP_LEN] = {0};
    char current_ip[MAX_IP_LEN] = {0};
    char current_iface[MAX_IFACE_LEN] = {0};

    get_active_interface_and_ip(current_iface, sizeof(current_iface), 
                             current_ip, sizeof(current_ip));
    strncpy(last_ip, current_ip, sizeof(last_ip) - 1);
    
    if (!daemon_mode) {
        printf("[*] Initial IP: %s (%s)\n", current_ip, current_iface);
    }

    if (target_count > 0 && is_target_ip(current_ip, targets, target_count)) {
        if (!daemon_mode) {
            printf("[✔] Initial IP matches target\n");
            return EXIT_SUCCESS;
        } else {
            log_message("[✔] Initial IP matches target\n");
        }
    }

    int attempt = 1;
    while (running) {
        if (!daemon_mode) {
            printf("\n[+] Attempt %d\n", attempt++);
        } else {
            log_message("\n[+] Attempt %d\n", attempt++);
        }

        toggle_airplane_mode(1);
        sleep(AIRPLANE_TOGGLE_DELAY);
        toggle_airplane_mode(0);

        wait_for_network();
        
        if (get_active_interface_and_ip(current_iface, sizeof(current_iface), 
                                      current_ip, sizeof(current_ip)) < 0) {
            if (!daemon_mode) {
                fprintf(stderr, "[-] Network info unavailable\n");
            }
            continue;
        }

        if (!daemon_mode) {
            printf("[*] New IP: %s (%s)\n", current_ip, current_iface);
        } else {
            log_message("[*] New IP: %s (%s)\n", current_ip, current_iface);
        }

        // Target check
        if (target_count > 0) {
            if (is_target_ip(current_ip, targets, target_count)) {
                if (!daemon_mode) {
                    printf("[✔] TARGET IP MATCHED\n");
                    break;
                } else {
                    log_message("[✔] TARGET IP MATCHED\n");
                }
            } else if (!daemon_mode) {
                printf("[!] Not a target IP\n");
            } else {
                log_message("[!] Not a target IP\n");
            }
        }

        // IP change detection
        if (strcmp(current_ip, last_ip) != 0) {
            if (!daemon_mode) {
                printf("[✔] IP CHANGED: %s → %s\n", last_ip, current_ip);
            } else {
                log_message("[✔] IP CHANGED: %s → %s\n", last_ip, current_ip);
            }
        } else if (!daemon_mode) {
            printf("[!] IP UNCHANGED\n");
        } else {
            log_message("[!] IP UNCHANGED\n");
        }
        strncpy(last_ip, current_ip, sizeof(last_ip) - 1);

        // Delay handling
        for (int i = 0; i < delay && running; i++) {
            sleep(1);
        }
    }

    if (daemon_mode) {
        log_message("[*] Daemon stopped\n");
    } else {
        printf("\n[*] Operation completed\n");
    }

    return EXIT_SUCCESS;
}
