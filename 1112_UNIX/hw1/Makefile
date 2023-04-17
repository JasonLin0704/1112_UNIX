all: s

s:
	gcc sandbox.c -o sandbox.so -shared -ldl -fPIC -g
1:
	./launcher ./sandbox.so config.txt cat /etc/passwd
2:
	./launcher ./sandbox.so config.txt cat /etc/hosts
3:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem
5:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1
6:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1
7:
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1
8:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'
9:
	./launcher ./sandbox.so config.txt cat /home/jason/UNIX/data/home/hw1/config.txt