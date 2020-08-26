/* comb2.c
 *
 * Recherche de toutes les combinaisons de p éléments de
 * l'ensemble {1, 2, 3, 4, 5, ..., n}
 * 
 * 01/05/2005 Jean-Paul Davalan <jpdvl@wanadoo.fr>
 *
 * compilation :  gcc -O2 -o comb2 comb2.c
 * usage : comb2 n p
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void combinaisons(int n, int p, int k, int *L, int *t, int r) {
	int i, j, j1, t2[n];
	if(r<p-k) return;
	if(k==p) {
                printf("\"");
		for(i=0;i<p;i++) printf("%d", L[i]);
		printf("\" ");
		return;
	}
	for(i=0;i<r;i++) {
		L[k] = t[i];
		for(j=i+1, j1=0;j<r;j++, j1++) {
			t2[j1] = t[j];
		}
		combinaisons(n, p, k+1, L, t2, j1);
	}
}

void effectue(int n, int p) {
        int L[p], t[n], i;
        for(i=0;i<n;i++)
                t[i] = i;
        combinaisons(n, p, 0, L, t, n);
}

int main(int argc, char *argv[]) {
 int n, p;
        if(argc<3) {
                printf("usage : %s n p\n",argv[0]);
                exit(1);
        }
        n = atoi(argv[1]); // lecture des paramètres
        p = atoi(argv[2]);
        if(n<0 || p<0 || p>n) return 0;
        effectue(n, p);
        printf("\n");

        return 0;
}

