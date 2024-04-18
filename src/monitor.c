#include "../include/antivirus.h"

char locked_filenames[MAX_EVENTS][MAX_LENGTH]; /* Global array to store the names of locked files */
int locked_files_count = 0; /* Global variable to keep track of the number of locked files */

char normal_files[MAX_EVENTS][MAX_LENGTH]; /* Global array to store the names of normal files */
int normal_files_count = 0; /* Global variable to keep track of the number of normal files */

int is_ransomware[MAX_EVENTS] = {0}; /*Array to keep track of ransomware status for each file */

void monitor_handle_events(int fd) {
    int len;
    char buf[BUF_LEN];

    len = read(fd, buf, BUF_LEN);
    if (len == -1 && errno != EAGAIN) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    for (char *ptr = buf; ptr < buf + len; ptr += EVENT_SIZE + ((struct inotify_event *) ptr)->len) {
        struct inotify_event *event = (struct inotify_event *) ptr;

        if (event->len) {
            if (event->mask & IN_CREATE) {
                printf("File '%s' was created\n", event->name);
                strcpy(normal_files[normal_files_count++], event->name);
                /* Check if a .locked file was created */
                if (strstr(event->name, ".locked") != NULL) {
                    strcpy(locked_filenames[locked_files_count++], event->name);
                }
            } else if (event->mask & IN_MODIFY) {
                printf("File '%s' was modified\n", event->name);
                /* Check if a .locked file was modified */
                if (strstr(event->name, ".locked") != NULL) {
                    for (int i = 0; i < locked_files_count; i++) {
                        if (strcmp(event->name, locked_filenames[i]) == 0) {
                            is_ransomware[i] = 1;
                            break;
                        }
                    }
                }
            } else if (event->mask & IN_DELETE) {
                printf("File '%s' was deleted from watched directory\n", event->name);
                /* Check if the original file was deleted but the .locked file was not */
                int found = 0;
                for (int i = 0; i < locked_files_count; i++) {
                    if (strstr(event->name, ".locked") != NULL && strcmp(locked_filenames[i], event->name) == 0) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    for (int i = 0; i < normal_files_count; i++) {
                        if (strcmp(event->name, normal_files[i]) == 0 && is_ransomware[i]) {
                            printf("[\033[1;31mWARN\033[0m]\033[1;31m Ransomware attack detected on file on file %s\033[0m\n", event->name);
                            break;
                        }
                    }
                }
            } else if (event->mask & IN_CLOSE_WRITE) {
                printf("File '%s' that was opened for writing was closed\n", event->name);
            } else if (event->mask & IN_OPEN) {
                printf("File '%s' was opened\n", event->name);
            } else if (event->mask & IN_CLOSE_NOWRITE) {
                printf("File '%s' that was not opened for writing was closed\n", event->name);
            } else if (event->mask & IN_ACCESS) {
                printf("File '%s' was accessed\n", event->name);
            }
        }
    }
}

void print_results_monitor(char* dir){
     int fd = inotify_init();
    if (fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, dir, IN_CREATE | IN_DELETE | IN_MODIFY | IN_CLOSE_WRITE | IN_ACCESS | IN_CLOSE_NOWRITE | IN_OPEN);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20]; 

    pid_t pid = getpid();

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, 20, "%d-%b-%y %H:%M:%S", timeinfo);

    printf("[INFO] [%d] [%s] Application Started\n", pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Scanning directory %s\n",pid , timestamp, dir);
    sleep(1);
    printf("[INFO] [%d] [%s] Waiting for events...\n", pid , timestamp);
    sleep(1);
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    
    while (1) {
        int ret = poll(fds, 1, -1);
        if (ret == -1) {
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (fds[0].revents & POLLIN) {
            monitor_handle_events(fd);
        }
    }

}