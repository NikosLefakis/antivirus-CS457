
/*****************************************************
 * @file   inspect.c                               *
 * @author Nikos Lefakis csd4804@csd.uoc.gr    *
 *                                                   *
 * @brief Implementation for inspect.c (Inspect mode) 				 *
 * Assignment 2 CS457: “Implementation of a Ransomware Protection Software Suite”					         *
 *****************************************************/ 


#include "../include/antivirus.h"


FileInfoInspect domains[MAX_DOMAINS]; 
int domain_counter = 0;
int file_count_inspect = 0;



/*for message of request*/
size_t curl_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char *response = (char *)userp;
    strncat(response, (char *)contents, realsize);
    return realsize;
}


/* Check for domain if malicious or not with help of Cloudflare (HTTP request)*/
int check_domain(char *domain) {
    CURL *curl;
    CURLcode res;
    char url[MAX_DOMAIN_LEN];
    char response[MAX_LINE_LEN];
    sprintf(url, "https://family.cloudflare-dns.com/dns-query?name=%s", domain);
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/dns-json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);  /*headers*/
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return -1;   /* error ara epistrefo kati pou den einai 0 h 1 */
        } else {
            if (strstr(response, "EDE(16): Censored") != NULL) {
                return 1; /*An periexei afto to "comment" to string response tote to 8ewroume malicious ara return 1*/
            }
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return 0;  /* return 0 gia safe domain*/
}

/* Check for duplicates to not include in array*/
int check_duplicates(char *dom) {
    for (int i = 0; i < domain_counter; i++) {
        if (strcmp(dom, domains[i].domain) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Remove prefix*/
char* removePrefix(char *domain) {
    if (strstr(domain, "https://") == domain) {
        memmove(domain, domain + 8, strlen(domain) - 7);
    }

    if (strstr(domain, "http://") == domain) {
        memmove(domain, domain + 7, strlen(domain) - 6);
    }

    if (strstr(domain, "www.") == domain) {
        memmove(domain, domain + 4, strlen(domain) - 3);
    }

    return domain;
}

void print_domains(char *dir) {
    
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
    printf("[INFO] [%d] [%s] Found %d files\n", pid ,timestamp, file_count_inspect);
    sleep(1);
    printf("[INFO] [%d] [%s] Searching…\n",pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Operation finished\n",pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Processed %d files.\n",pid , timestamp, file_count_inspect);
    sleep(1);
    printf("| FILE                    | PATH                                      | DOMAIN         | EXECUTABLE | RESULT   |\n");
    printf("==================================================================================================================\n");
    for (int i = 0; i < domain_counter; i++) {
        const char *filename = basename(domains[i].filename);
        const char *filepath = domains[i].filepath;
        const char *domain = domains[i].domain;
        struct stat file_stat;
        const char *executable;
        /*check if a file is executable or not*/
        if (stat(filepath, &file_stat) == 0) {
            if (file_stat.st_mode & S_IXUSR) {
                executable = "True";
            } else {
                executable = "False";
            }
        } else {
            executable = "N/A";
        }
        const char *result = check_domain(domains[i].domain) ? "\x1b[31mMalware\x1b[0m" : "\x1b[32mSafe\x1b[0m";
        printf("| %-24s| %-42s| %-14s| %-10s| %-8s|\n", filename, filepath, domain, executable, result);
    }
}

/*  extract domains from files with custom pattern for regular expressions */
void scan_file(char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "Cannot open file: %s\n", path);
        return;
    }

    regex_t regex;
    int reti;
    char line[MAX_LINE_LEN];
    char* pattern = "(http://|https://|www\\.)([a-zA-Z0-9-]+\\.?)+[a-zA-Z0-9-]+\\.(com|org|net|edu|gov|mil|int|info|biz|mobi|name|pro|gr)|[a-zA-Z0-9-]+\\.(com|org|net|edu|gov|mil|int|info|biz|mobi|name|pro|gr)";


    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        return;
    }

    while (fgets(line, MAX_LINE_LEN, file) != NULL) {
        regmatch_t matches[1];
        char *cursor = line;
        while (regexec(&regex, cursor, 1, matches, 0) == 0) {
            char* domain = malloc(MAX_DOMAIN_LEN);
            int len = matches[0].rm_eo - matches[0].rm_so;
            strncpy(domain, cursor + matches[0].rm_so, len);
            domain[len] = '\0';
            domain = removePrefix(domain);
            if (!check_duplicates(domain)) {
                strncpy(domains[domain_counter].filename, path, MAX_LINE_LEN);
                strncpy(domains[domain_counter].filepath, path, MAX_LINE_LEN);
                strncpy(domains[domain_counter].domain, domain, MAX_DOMAIN_LEN);
                domain_counter++;
            }
            cursor += matches[0].rm_eo;    
        }
    }

    regfree(&regex);
    fclose(file);
}


/* Traverse directory and do actions */
void traverse_directory_inspect(char *dir) {
    DIR *dp;
    struct dirent *entry;
    char path[MAX_PATH];

    if ((dp = opendir(dir)) == NULL) {
        fprintf(stderr, "Cannot open directory: %s\n", dir);
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);

        if (entry->d_type == DT_DIR) {
            traverse_directory_inspect(path);
        } else if (entry->d_type == DT_REG) {
            file_count_inspect++;
            scan_file(path);
        }
    }

    closedir(dp);
}

/*----------------------------------------------------------------------------------------------------------------*/