goto-zero: goto-zero.c
	gcc -m64 -ogoto-zero -fno-stack-protector -Wstringop-overflow=0 -no-pie goto-zero.c

clean:
	rm -f *.o goto-zero
