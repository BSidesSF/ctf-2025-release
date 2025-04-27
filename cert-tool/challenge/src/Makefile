all: cert-tool

cert-tool: cert-tool.c
	gcc -o cert-tool -O3 -Wall cert-tool.c
	strip cert-tool

clean:
	rm -f *.o cert-tool
