all: build

build:
	javac -d bin `find team -name *.java`
