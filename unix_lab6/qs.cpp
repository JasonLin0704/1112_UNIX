#include <iostream>
#include <utility>
#include <random>
using namespace std;

void q(int *a, int l, int r);
void insertion(int *a, int l, int r);

int main(){
    int a[100];
    int n = 100;
    for(int i = 0; i < n; i++){
        a[i] = rand() % 101 - 50;
    }

    for(int i = 0; i < n; i++) cout << a[i] << " ";
    cout << "\n------------\n";
    
    // q(a, 0, n - 1);
	insertion(a, 0, n - 1);

    for(int i = 0; i < n; i++) cout << a[i] << " ";
    cout << "\n------------\n";

    return 0;
}

void insertion(int *a, int l, int r){
    l += 1;
	for(; l <= r; l++){
        int key = a[l];				    //key: 要往前插入的那個數 
        int j = l;
		while(j > 0 && a[j-1] > key){   //a[0], a[1], ..., a[i-1] 依序跟 a[i] 做比較 	
			a[j] = a[j-1];				//若 a[i-1]較大，把 a[i-1]往後搬一格
			j--;                         
		}		 					 	
        a[j] = key;        
    }
}

// i, l: r8
// insertion key: r13
// j: r14

void q(int *a, int l, int r){
	if(l < r){
        int pivot = a[l]; 	//設定 pivot為數列第一個數
        int i = l;
		int j = r + 1;
		
		/* 步驟一：將數列用 pivot分成左右數列  */
		do{
			do i++; while(i <= r && a[i] < pivot);	//從左找第一個大於 pivot的數 → 
			do j--; while(j >= l && a[j] > pivot); 	//從右找第一個小於 pivot的數 ← 
			if(i < j) swap(a[i], a[j]); 			//若找到，且沒有交錯，則將兩數交換 
		} while(i < j); 							//直到i,j交錯 

		
		swap(a[j], a[l]);  	//a[j]跟 pivot交換 (a[j]比 pivot小，調到最前面沒問題) 
							//此時位置 j為 pivot，j左邊都小，j右邊都大 						 
		
		/* 步驟二：針對左右數列重複QuickSort */
		q(a, l, j - 1);
		q(a, j + 1, r);
	}
}

// array: rdi
// n: rsi
// l: r8
// r: r9
// pivot: r12
// i: rcx
// j: rdx

// mov rax, [rdi + rcx * 8]
// mov rbx, [rdi + rdx * 8]
// mov [rdi + rcx * 8], rbx
// mov [rdi + rdx * 8], rax

// mov rax, [rdi + rcx * 8]
// xchg [rdi + rdx * 8], rax
// mov [rdi + rcx * 8], rax