cmd_/home/sense/Downloads/lab5/hellomod/hellomod.mod := printf '%s\n'   hellomod.o | awk '!x[$$0]++ { print("/home/sense/Downloads/lab5/hellomod/"$$0) }' > /home/sense/Downloads/lab5/hellomod/hellomod.mod
