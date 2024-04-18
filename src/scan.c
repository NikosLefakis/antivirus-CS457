#include "../include/antivirus.h"

InfectedFiles infected_files[MAX_FILES];
int num_infected_files = 0;
int total_files_scan = 0;

/*---------------------Scan mode------------------------------------------------------------------------*/
void calculate_md5(char *filename, char *md5sum) {
    if (md5sum == NULL) return;

    FILE *file;
    unsigned char final[MD5_DIGEST_LENGTH];

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }

    MD5_CTX context;
    MD5_Init(&context);
    int bytes;
    unsigned char data[1024];
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        MD5_Update(&context, data, bytes);
    }
    MD5_Final(final, &context);

    fclose(file);

    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&md5sum[i*2], "%02x", final[i]);
    }
     md5sum[MD5_DIGEST_LENGTH*2] = '\0'; 
}

void calculate_sha256(char *filename, char *sha256sum) {

    if(sha256sum == NULL) return;

    FILE *file;
    unsigned char final[SHA256_DIGEST_LENGTH];

    file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }

    SHA256_CTX context;
    SHA256_Init(&context);
    int bytes;
    unsigned char data[1024];
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        SHA256_Update(&context, data, bytes);
    }
    SHA256_Final(final, &context);

    fclose(file);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&sha256sum[i*2], "%02x", (unsigned int)final[i]);
    }
    sha256sum[SHA256_DIGEST_LENGTH*2] = '\0';


}

void check_files_indicators(char* pathname){
    char digest_md5[MD5_DIGEST_LENGTH * 2 + 1];
    char digest_sha256[SHA256_DIGEST_LENGTH * 2 + 1];

    calculate_md5(pathname, digest_md5);
    calculate_sha256(pathname, digest_sha256);

    /* check for md5 hash malicious */
    char* md5_malicious = "85578cd4404c6d586cd0ae1b36c98aca";
    if (strstr(digest_md5, md5_malicious) != NULL) {
        infected_files[num_infected_files].path = strdup(pathname);
        infected_files[num_infected_files].message = strdup("\033[1;31mREPORTED_MD5_HASH\033[0m");
        num_infected_files++;
    }

    /* check for sha256 hash malicious */
    char* sha256_malicious = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
    if (strstr(digest_sha256, sha256_malicious) != NULL) {
        infected_files[num_infected_files].path = strdup(pathname);
        infected_files[num_infected_files].message = strdup("\033[1;31mREPORTED_SHA256_HASH\033[0m");
        num_infected_files++;
    }

    /* check for bitcoin address */
    char* bitcoin_address = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
    FILE *fp = fopen(pathname, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, bitcoin_address) != NULL) {
                infected_files[num_infected_files].path = strdup(pathname);
                infected_files[num_infected_files].message = strdup("\033[1;31mREPORTED_BITCOIN\033[0m");
                num_infected_files++;
                break;
            }
        }
        fclose(fp);
    }

    /* check for virus signature */
    unsigned char signature[] = {0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff,0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
    size_t signatureSize = sizeof(signature);

    FILE *file = fopen(pathname, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }

    unsigned char buffer;
    size_t bytesRead;
    size_t matchedBytes = 0;

    while ((bytesRead = fread(&buffer, sizeof(unsigned char), 1, file)) > 0) {
        if (buffer == signature[matchedBytes]) {
            matchedBytes++;
            if (matchedBytes == signatureSize) {
                infected_files[num_infected_files].path = strdup(pathname);
                infected_files[num_infected_files].message = strdup("\033[1;31mREPORTED_VIRUS\033[0m");
                num_infected_files++;
                break;  
            }
        } else {
            matchedBytes = 0; 
        }
    }
    fclose(file);
}

void scan_directories(char* dirname) {
    DIR* dir;
    struct dirent* entry;

    if (!(dir = opendir(dirname))) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[1024];

         if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) 
                continue;
        
         snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);
        if (entry->d_type == DT_DIR) {
            scan_directories(path);
        } else if (entry->d_type == DT_REG) {
            check_files_indicators(path);
            total_files_scan++;
        }
    }
    closedir(dir);
}

void print_results(char* dir) {
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20]; 

    pid_t pid = getpid();

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, 20, "%d-%b-%y %H:%M:%S", timeinfo); // Format the timestamp

    printf("[INFO] [%d] [%s] Application Started\n", pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Scanning directory %s\n",pid , timestamp, dir);
    sleep(1);
    printf("[INFO] [%d] [%s] Found %d files\n", pid ,timestamp, total_files_scan);
    sleep(1);
    printf("[INFO] [%d] [%s] Searching…\n",pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Operation finished\n",pid , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Processed %d files. \033[1;31mFound %d infected\033[0m\n\n",pid , timestamp, total_files_scan, num_infected_files);
    sleep(1);

    for (int i = 0; i < num_infected_files; i++) {
        printf("[%s] %s: %s\n", timestamp, infected_files[i].path, infected_files[i].message);
    }
}
