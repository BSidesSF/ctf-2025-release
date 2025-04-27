all: obscuratron memo.pdf.enc

obscuratron: obscuratron.c
	gcc -Wall -fPIE -o obscuratron obscuratron.c
	strip obscuratron

memo.pdf.enc: memo.pdf obscuratron
	./obscuratron 2>/dev/null < memo.pdf > memo.pdf.enc

clean:
	rm -f *.o *.enc obscuratron

