all: drago-daction

drago-daction: drago-daction.c
	gcc -o drago-daction -m64 -fstack-protector-strong -no-pie drago-daction.c

clean:
	rm -f *.o drago-daction
