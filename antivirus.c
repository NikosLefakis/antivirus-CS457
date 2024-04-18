#include "include/antivirus.h"

int main(int argc , char* argv[]){
    if (argc != 3) {
        fprintf(stderr, "Usage:  %s [scan/inspect/monitor/slice] <directory>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if(!strcmp(argv[1],"scan")){
         char *dir = argv[2];
         scan_directories(dir);
         print_results(dir);
    }
    else if(!strcmp(argv[1], "inspect")){
        char *dir = argv[2];
        traverse_directory_inspect(dir);
        print_domains(dir);
    }
    else if(!strcmp(argv[1], "monitor")){
        char* dir = argv[2];
        print_results_monitor(dir);
    }
    
    return 0;
}


