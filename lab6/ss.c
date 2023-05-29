#include <stdio.h>

void selection(int *a, int n){
    for(int i = 0; i < n; i++){
        int m = i;
        for(int j = i + 1; j < n; j++){
            if(a[j] < a[m]) m = j;
        }
        int tmp = a[i];
        a[i] = a[m];
        a[m] = tmp;
    }

    // rdi: array
    // rsi: n
    // rcx: i
    // rdx: j
    // r8: m
}

int main(){
    int a[100] = {0};
    for(int i = 0; i < 100; i++) a[i] = 100 - i;

    for(int i = 0; i < 100; i++) printf("%d\n", a[i]);

    selection(a, 100);

    printf("------------------\n");
    for(int i = 0; i < 100; i++) printf("%d\n", a[i]);

    return 0;
}
