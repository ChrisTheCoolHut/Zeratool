#include <stdio.h>

#ifdef win_func
void print_flag()
{
    puts("flag{you_did_it}");
    system("cat flag.txt");
}
#endif

int pwn_me()
{
    char my_buf[20] = {'\x00'};
    printf("Your buffer is at %p\n", my_buf);
    gets(my_buf);
    return 0;
}

void does_nothing()
{
    puts("/bin/sh");
    execve(NULL,NULL,NULL);
}

void main()
{
    puts("pwn_me:");
    pwn_me();
}