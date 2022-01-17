all: helloWorld;

helloWorld: helloWorld.o
	g++ -o helloWorld helloWorld.o

helloWorld.o: helloWorld.cpp
	g++ -c helloWorld.cpp

clean:
	rm -f helloWorld.o helloWorld
