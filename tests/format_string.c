#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * compiled with:
 * gcc -O0 -fno-stack-protector -o hard -z execstack -z norelro hard.c
 * run with:
 * socat TCP4-LISTEN:7803,tcpwrap=script,reuseaddr,fork EXEC:./hard
 */

#define FLAG_NAME "flag.txt"

#ifdef MEDIUM
/*
 * Test for point to win
 */
void secret_function(void) {
    char key[50] = {0};
    FILE *pFile = NULL;
    pFile = fopen(FLAG_NAME, "r");
    fread(key, sizeof(key), 1, pFile);
    printf("The flag is %s\n", key);
    system("cat flag.txt");
}
#endif

int main(int argc, char *argv[])
{
    int i = 0;

#ifdef EASY
    char buf[1024];
    fgets(buf, 1024, stdin);
    /*
     * Test for stack reading
     */
    char key[64]={};
    FILE *pKey = fopen(FLAG_NAME, "r");
    if (pKey == NULL)
    {
      printf("No .pass\nContact admin\n");
      return -1;
    }
    fread(&key, sizeof(key), 1, pKey);
    fclose(pKey);
#endif

#ifdef MEDIUM
    char buf[256];
    read(0, buf, 256);
#endif
    
#ifdef HARD
    char buf[1024];
    /* read user input securely */
    fgets(buf, 1024, stdin);
    /*
     * Test for point to shellcode AND
     * satisfy constraints
     */
    /* convert string to lowercase */
    for (i = 0; i < strlen(buf); i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z')
            buf[i] = buf[i] ^ 0x20;
#endif

    /* print out our nice and new lowercase string */
    printf(buf);

    exit(EXIT_SUCCESS);
    return EXIT_FAILURE;
}
