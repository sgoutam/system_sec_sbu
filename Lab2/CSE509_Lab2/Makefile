default: url2file

url2file.o: url2file.c 
	gcc -c url2file.c -o url2file.o

url2file: url2file.o
	gcc url2file.o -o url2file

clean:
	-rm -f url2file.o
	-rm -f url2file
