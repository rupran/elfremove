#include"testbib.h"

int subtest(int a, int b){
    int ret = a-b;
    //if(ret > a || ret > b)
    return ret;
}

int addtest(int a, int b){
    int ret = a+b;
    if(ret < a || ret < b) return 0;
    return ret;
}

int multest(int a, int b){
    int ret = a*b;
    if(ret / b != a) return 0;
    return ret;
}

int divtest(int a, int b){
    if(a*b == 0) return 0;
    return a / b;
}
