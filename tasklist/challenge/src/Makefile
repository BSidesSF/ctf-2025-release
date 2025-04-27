NAME=tasklist
SRCS=tasklist.c

${NAME}: ${NAME}.dbg
	strip -s -o $@ $<

${NAME}.dbg: ${SRCS} crypted.h
	gcc -o $@ -O0 -g -Wall -Wextra -Werror -std=c99  -static-libgcc ${SRCS} -static -lm -lc

crypted.h: encrypt.py
	python3 encrypt.py $@

clean:
	rm -f *.o ${NAME} ${NAME}.dbg
