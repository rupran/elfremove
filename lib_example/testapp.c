#include"testbib.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    if(argc != 4){
        printf("\nUsage: %s [1-4] number1 number2\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int func = atoi(argv[1]);
    int no1 = atoi(argv[2]);
    int no2 = atoi(argv[3]);
    int erg = 0;

    switch(func){
        case 1:
//            erg = addtest(no1, no2);
            break;
        case 2:
            erg = subtest(no1, no2);
            break;
        case 3:
            erg = multest(no1, no2);
            break;
        case 4:
            erg = divtest(no1, no2);
            break;
        default:
            printf("\nUsage: %s [1-4] number1 number2\n", argv[0]);
            exit(EXIT_FAILURE);
    }
    printf("\nSolution: %d\n", erg);
    exit(EXIT_SUCCESS);
}
