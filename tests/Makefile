
build_flags := -fno-stack-protector -z execstack \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -fcf-protection=none -mno-shstk
build_NX_flags := -fno-stack-protector \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -z relro -fcf-protection=none -mno-shstk
bin_names := bof_32 bof_64 bof_win_32 bof_win_64 \
	read_stack_32 format_pc_write_32 format_write_and_constrain_32 \
	read_stack_64 format_pc_write_64 format_write_and_constrain_64 \
	flag.txt

CC := gcc

all: build_bof build_format_32 build_format_64 build_flag

build_bof:
	$(CC) -m32 buffer_overflow.c -o bin/bof_32 $(build_flags)
	$(CC) buffer_overflow.c -o bin/bof_64 $(build_flags)
	$(CC) -m32 buffer_overflow.c -o bin/bof_nx_32 $(build_NX_flags)
	$(CC) buffer_overflow.c -o bin/bof_nx_64 $(build_NX_flags)
	$(CC) -m32 buffer_overflow.c -o bin/bof_win_32 -Dwin_func $(build_flags)
	$(CC) buffer_overflow.c -o bin/bof_win_64 -Dwin_func $(build_flags)

	$(CC) buffer_overflow.c -o bin/bof_srop_64 -Dsrop_func $(build_flags)
	$(CC) buffer_overflow.c -o bin/bof_dlresolve_64 -Ddlresolve_read_func \
		-fno-stack-protector -no-pie -z norelro -Wno-nonnull

build_format_32:
	$(CC) -O0 -m32 -fno-stack-protector -o bin/read_stack_32 \
		format_string.c -DEASY $(build_flags)
	$(CC) -O0 -m32 -fno-stack-protector -o bin/format_pc_write_32 \
		format_string.c -DMEDIUM $(build_flags) -z relro
	$(CC) -O0 -m32 -fno-stack-protector -o bin/format_write_and_constrain_32 \
		format_string.c -DHARD $(build_flags)

build_format_64:
	$(CC) -O0 -fno-stack-protector -o bin/read_stack_64 \
		format_string.c -DEASY $(build_flags)
	$(CC) -O0 -fno-stack-protector -o bin/format_pc_write_64 \
		format_string.c -DMEDIUM $(build_flags) -z relro
	$(CC) -O0 -fno-stack-protector -o bin/format_write_and_constrain_64 \
		format_string.c -DHARD $(build_flags)

build_flag:
	echo "flag{y0u_g0t_1t}" > flag.txt
	cp flag.txt ../

clean:
	rm -rf bin/*