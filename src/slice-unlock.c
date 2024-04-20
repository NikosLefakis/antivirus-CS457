#include "../include/antivirus.h"


pid_t pid_process(){
    return getpid();
}

/* Function to generate a random number with custom range */  
int generate_random_number(int min, int max) {
    return rand() % (max - min + 1) + min;
}

/* Function to evaluate the polynomial at a given point */
int evaluate_polynomial(int a2, int a1, int a0, int x) {
    return a2 * x * x + a1 * x + a0;
}

// Function to generate shares for a given secret
void generate_shares(int secret, int shares[MAX_MEMBERS][2]) {
    /* Generate random  a2, a1, and a0 coefficients */
    /* You put your custom range for example (100-999)*/
    computed_number[0] = generate_random_number(10, 99);
    computed_number[1] = generate_random_number(100, 999);
    int a0 = secret; 

   
    /* Generate pairs of shares */
    for (int i = 0; i < MAX_MEMBERS; i++) {
        int share_x = i + 1;
        int share_y = evaluate_polynomial(computed_number[1], computed_number[0], a0, share_x);
        shares[i][0] = share_x;
        shares[i][1] = share_y;
    }
}


int reconstruct_secret(int shares[MAX_MEMBERS][2], int provided_shares[MAX_MEMBERS][2], int num_provided_shares) {
    /* Initialize variables for the coefficients of the polynomial */
    double a2 = 0, a1 = 0, a0 = 0;


   /*Reconstruct the polynomial*/
    for (int i = 0; i < num_provided_shares; i++) {
        double term = 1;
        for (int j = 0; j < num_provided_shares; j++) {
            if (i != j) {
                term *= -provided_shares[j][0] / (double)(provided_shares[i][0] - provided_shares[j][0]);
            }
        }
        a2 += term;
        a1 += term * (-provided_shares[i][0]);
        a0 += term * provided_shares[i][1];
    }   
    return a0;
}

void print_slice(int secret_number){
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20]; 

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, 20, "%d-%b-%y %H:%M:%S", timeinfo); 
    printf("[INFO] [%d] [%s] Application Started\n", pid_process() , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Generating shares for key '%d'\n", pid_process() , timestamp , secret_number);
    sleep(1);
       
     /* Print the generated shares */
    printf("Generated shares:\n");
    for (int i = 0; i < MAX_MEMBERS; i++) {
        printf("(%d, %d)\n", shares[i][0], shares[i][1]);
    }
}


void print_unlock_provided_share(int reconstructed_number , int provided_share_number){
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20]; 

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, 20, "%d-%b-%y %H:%M:%S", timeinfo); 

    printf("[INFO] [%d] [%s] Application Started\n", pid_process() , timestamp);
    sleep(1);
    printf("[INFO] [%d] [%s] Received %d different shares\n", pid_process() , timestamp,provided_share_number);
    sleep(1);
    printf("[INFO] [%d] [%s] Computed that a=%d and b=%d\n", pid_process() , timestamp,computed_number[0],computed_number[1]);
    sleep(1);
    printf("[INFO] [%d] [%s] Encryption key is: \033[0;34m%d\033[0m\n", pid_process() , timestamp , reconstructed_number);
    sleep(1);

}
