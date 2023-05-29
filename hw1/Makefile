config-ex = config-example.txt
config = config.txt

all: s

s:
	gcc sandbox.c -o sandbox.so -shared -ldl -fPIC -g
1:
	./launcher ./sandbox.so $(config-ex) cat /etc/passwd
2:
	./launcher ./sandbox.so $(config-ex) cat /etc/hosts
3:
	./launcher ./sandbox.so $(config-ex) cat /etc/ssl/certs/Amazon_Root_CA_1.pem
5:
	./launcher ./sandbox.so $(config-ex) wget http://google.com -t 1
6:
	./launcher ./sandbox.so $(config-ex) wget https://www.nycu.edu.tw -t 1
7:
	./launcher ./sandbox.so $(config-ex) wget http://www.google.com -q -t 1
8:
	./launcher ./sandbox.so $(config-ex) python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'

h1:
	./launcher ./sandbox.so $(config) cat /tmp/testfile ; ./launcher ./sandbox.so config.txt cat /etc/passwd ; ./launcher ./sandbox.so config.txt cat /etc/hosts
h2:
	./launcher ./sandbox.so $(config) wget http://google.com/ -t 1 -o /dev/null ; ./launcher ./sandbox.so config.txt wget http://linux.cs.nctu.edu.tw ; ./launcher ./sandbox.so config.txt wget https://freebsd.cs.nctu.edu.tw
h3:
	./launcher ./sandbox.so $(config) ./case3