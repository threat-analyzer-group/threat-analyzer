all: build

BUILD_DIR = bin

build:
	javac -d ${BUILD_DIR} `find team -name *.java`

clean:
	rm -rf ${BUILD_DIR}/team
