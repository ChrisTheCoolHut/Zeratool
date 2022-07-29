#include <stdio.h>

#ifdef win_func
void print_flag()
{
    puts("flag{you_did_it}");
    system("cat flag.txt");
}
#endif

#ifdef srop_func
__attribute__((naked)) void syscall_gad()
{
    __asm__("syscall");
    __asm__("ret");
}
__attribute__((naked)) void pop_rax()
{
    __asm__("pop %rax");
    __asm__("ret");
}
__attribute__((naked)) void pop_rdi()
{
    __asm__("pop %rdi");
    __asm__("ret");
}
#endif

#ifdef dlresolve_read_func

void give_gadgets()
{
    __asm__("pop %rdx");
    __asm__("ret");
}

int pwn_me()
{
    char my_buf[20] = {'\x00'};
    printf("Your buffer is at %p\n", my_buf);
    read(0, my_buf, 230);
    return 0;
}

#else

int pwn_me()
{
    char my_buf[20] = {'\x00'};
    printf("Your buffer is at %p\n", my_buf);
    gets(my_buf);
    return 0;
}

#endif



void does_nothing()
{
    puts("/bin/sh");
    execve(NULL,NULL,NULL);
}

__attribute__ ((constructor)) void ignore_me()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

void main()
{

    puts("pwn_me:");
    pwn_me();
}