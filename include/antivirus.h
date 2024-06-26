
/*****************************************************
 * @file   antivirus.h                                  *
 * @author Nikos Lefakis csd4804@csd.uoc.gr    *
 *                                                   *
 * @brief Implementation for antivirus.h (Function's declaration) 				 *
 * Assignment 2 CS457: “Implementation of a Ransomware Protection Software Suite”					         *
 *****************************************************/ 

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
#include <errno.h>
#include <sys/inotify.h>
#include <poll.h>
#include <sched.h>


#define MAX_PATH 4096
#define MAX_DOMAIN_LEN 256
#define MAX_LINE_LEN 2048
#define MAX_DOMAINS 4096
#define MAX_FILES 4096
#define MAX_MEMBERS 10

#define MAX_EVENTS 10
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))
#define MAX_LENGTH 1024

typedef struct{
    char* path;
    char* message;
}InfectedFiles;

int shares[MAX_MEMBERS][2];
int computed_number[2];


/*-------------- For Scan Mode -----------------------------------------------------------*/

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

/*-------------- For Inspect Mode -----------------------------------------------------------*/

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


/*-------------- For Monitor Mode -----------------------------------------------------------*/

/*Function that handle events with help of inotify library */
void monitor_handle_events(int fd);

/*Function to print result in monitor mode */
void print_results_monitor(char* dir);

/*-------------- For Slice - Unlock Mode-----------------------------------------------------------*/

/* Function to take process id */
pid_t pid_process();

/* Function to generate a random number with custom range */ 
int generate_random_number(int min, int max);

/* Function to evaluate the polynomial at a given point */
int evaluate_polynomial(int a2, int a1, int a0, int x);

/* Function to generate shares for a given secret */
void generate_shares(int secret, int shares[MAX_MEMBERS][2]);

/* Function to reconstruct the secret number from provided shares*/
int reconstruct_secret(int shares[MAX_MEMBERS][2], int provided_shares[MAX_MEMBERS][2], int num_provided_shares);

/* Function to print the slice (pairs of shares) */
void print_slice(int secret_number);

/* Function to print messages in unlock mode */
void print_unlock_provided_share(int reconstructed_number , int provided_share_number);

/*----------------------------------------------------------------------------------------------------------------------------------*/