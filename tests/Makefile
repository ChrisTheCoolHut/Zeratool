
build_flags := -fno-stack-protector -z execstack -Wno-implicit-function-declaration -no-pie
bin_names := bof_32 bof_64 bof_win_32 bof_win_64

build:
	gcc -m32 buffer_overflow.c -o bof_32 $(build_flags)
	gcc buffer_overflow.c -o bof_64 $(build_flags)
	gcc -m32 buffer_overflow.c -o bof_win_32 -Dwin_func $(build_flags)
	gcc buffer_overflow.c -o bof_win_64 -Dwin_func $(build_flags)
clean:
	rm $(bin_names)