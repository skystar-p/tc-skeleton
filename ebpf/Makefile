all:
	clang -O2 -fno-stack-protector -g -Wall -Werror -emit-llvm -c drop.c -o - | llc -march=bpf -mcpu=probe -filetype=obj -o drop

clean:
	-$(RM) drop
