#include <stdio.h>
#include <string.h>

unsigned char pt[256];
unsigned char key[256];
unsigned char s[256];

void swap(unsigned char *a, unsigned char *b){
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void getInput(unsigned char *pt, unsigned char *key){
    printf("Plaintext: ");
    fgets((char*)pt, 256, stdin);
    int len = strlen((char*)pt);
    if (len > 0 && pt[len-1] == '\n')
        pt[len-1] = '\0';

    printf("Key: ");
    fgets((char*)key, 256, stdin);
    len = strlen((char*)key);
    if (len > 0 && key[len-1] == '\n')
        key[len-1] = '\0';
}


void KSA(unsigned char *key, int key_len){
    for (int i=0; i<256; i++) s[i] = i;
    int j = 0;
    for (int i=0; i<256; i++){
        j = (j + s[i] + key[i % key_len]) % 256;
        swap(&s[i], &s[j]);
    }
}

void PRGA(unsigned char *pt, int pt_len, unsigned char *keystream){
    int i = 0, j = 0;
    for (int k=0; k<pt_len; k++){
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        swap(&s[i], &s[j]);
        int val = (s[i] + s[j]) % 256;
        keystream[k] = s[val];
    }
}

void xoring(unsigned char *pt, int pt_len, unsigned char *keystream, unsigned char *ct){
    for (int i=0; i<pt_len; i++){
        ct[i] = pt[i] ^ keystream[i];
    }
}

int main(){
    unsigned char keystream[256];
    unsigned char ct[256];
    getInput(pt, key);
    int pt_len = strlen(pt);
    int key_len = strlen(key);
    KSA(key, key_len);
    PRGA(pt, pt_len, keystream);
    xoring(pt, pt_len, keystream, ct);
    printf("Encrypted text: ");
    for (int i=0; i<pt_len; i++){
        printf("%02X", ct[i]);
    }
    printf("\n");

    return 0;

}
