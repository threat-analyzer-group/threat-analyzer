all: build

build:
	javac -d bin -analyzer `find team -name *.java`
