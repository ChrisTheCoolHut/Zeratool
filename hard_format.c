//gcc -O0 -fno-stack-protector -o hard -z execstack -z norelro hard_format.c -no-pie -m32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * compiled with:
 * gcc -O0 -fno-stack-protector -o hard -z execstack -z norelro hard.c
 * run with:
 * socat TCP4-LISTEN:7803,tcpwrap=script,reuseaddr,fork EXEC:./hard
 */

int main(int argc, char *argv[])
{
    int i = 0;
    char buf[300];

    /* read user input securely */
    fgets(buf, 300, stdin);

    /* convert string to lowercase */
/*    for (i = 0; i < strlen(buf); i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z')
            buf[i] = buf[i] ^ 0x20;*/

    /* print out our nice and new lowercase string */
    printf(buf);

    exit(EXIT_SUCCESS);
    return EXIT_FAILURE;
}

