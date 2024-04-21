
/*****************************************************
 * @file   antivirus.c                                 *
 * @author Nikos Lefakis csd4804@csd.uoc.gr    *
 *                                                   *
 * @brief Implementation for antivirus.c (main with commands from CLI) 				 *
 * Assignment 2 CS457: “Implementation of a Ransomware Protection Software Suite”					         *
 *****************************************************/ 

#include "include/antivirus.h"

int main(int argc , char* argv[]){

    srand((unsigned)time(NULL));

    if (argc < 3) {
        fprintf(stderr, "Usage:  %s [scan/inspect/monitor] <directory> or \n", argv[0]);
        fprintf(stderr, "Usage:  %s slice <number> or \n", argv[0]);
        fprintf(stderr, "Usage:  %s unlock <x1,y1 x2,y2 .... xn,yn> . \n", argv[0]);
        return EXIT_FAILURE;
    }
    
    
     int secret_number = atoi(argv[2]); /* for slice command*/
     // Check if the provided number is positive
     
    generate_shares(secret_number, shares);

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
    else if(!strcmp(argv[1], "slice")){
       print_slice(secret_number);
    }else if (!strcmp(argv[1], "unlock")) {

        if(argc < 5){
            printf("Give at least 3 pairs of shares!\n");
            exit(EXIT_FAILURE);
        }
        int provided_shares[MAX_MEMBERS][2];
        int num_provided_shares = argc - 2;
        for (int i = 0; i < num_provided_shares; i++) {
            /* Tokenize each provided share using strtok */
            char *token;
            token = strtok(argv[i + 2], "(,)");
            int j = 0;
            while (token != NULL) {
                
                provided_shares[i][j] = atoi(token);
                token = strtok(NULL, "(,)");
                j++;
            }

            /* Check if both x and y values are provided */
            if (j != 2) {
                printf("Invalid input format for provided shares.\n");
                exit(EXIT_FAILURE);
            }
        }

        /* Reconstruct the secret using the provided shares */
        int reconstructed_secret = reconstruct_secret(shares , provided_shares, num_provided_shares);
        
        /* Print the encryption key */ 
        print_unlock_provided_share(reconstructed_secret , num_provided_shares);

}
    return EXIT_SUCCESS;
}


