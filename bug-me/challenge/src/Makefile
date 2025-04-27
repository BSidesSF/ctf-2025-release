
bug-me: bug-me.c embed.rb
	gcc -rdynamic -o bug-me -O0 -Wall bug-me.c
	strip --keep-symbol=__gmon_init__ --keep-symbol=__gmon_map__ --keep-symbol=main bug-me
	ruby ./embed.rb

clean:
	rm -f *.o bug-me matchers/*.o matchers/*.bin
