#define _GNU_SOURCE
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <curl/curl.h>
#include <regex.h>
#include <sys/stat.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <sys/inotify.h>
#include <poll.h>
#include <sched.h>


#define MAX_PATH 4096
#define MAX_DOMAIN_LEN 256
#define MAX_LINE_LEN 2048
#define MAX_DOMAINS 4096
#define MAX_FILES 4096

#define MAX_EVENTS 10
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))
#define MAX_LENGTH 1024

typedef struct{
    char* path;
    char* message;
}InfectedFiles;


/*-------------- For Scan -----------------------------------------------------------*/

/*Function to calculate the MD5 hash of a file */
void calculate_md5(char *filename, char *md5sum);

/* Function to calculate the SHA256 hash of a file */
void calculate_sha256(char *filename, char *sha256sum);

/* Function to check files according to indicators  of Compromise*/
void check_files_indicators(char* pathname);

/* recursive function to scan directories */
void scan_directories(char* dirname);

/* Function to print results in scan mode */
void print_results(char* dir);

/*-------------- For Inspect -----------------------------------------------------------*/

typedef struct {
    char filename[MAX_PATH];
    char filepath[MAX_PATH];
    char domain[MAX_DOMAIN_LEN];
} FileInfoInspect;

/* Function for response of HTTPrequest in Cloudflare and with help of CURLOT_WRITEFUNCTION of curl library*/
size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp);

/*Function to check if a domain is malicious or safe and return a boolean result*/
int check_domain(char *domain);

/*Function to check for duplicate domains and not put in global array of domains*/
int check_duplicates(char *dom);

/*Function to remove prefixes from domains*/
char* removePrefix(char *domain);

/*Function to print results in inspect mode*/
void print_domains(char *dir);

/*Function to extract domains */
void scan_file(char *path);

/*Function to traverse directories and inspect files*/
void traverse_directory_inspect(char *dir);


/*-------------- For Monitor -----------------------------------------------------------*/

/*Function that handle events with help of inotify library */
void monitor_handle_events(int fd);

/*Function to print result in monitor mode */
void print_results_monitor(char* dir);

