cmd_/home/lab5/hellomod/hellomod.mod := printf '%s\n'   hellomod.o | awk '!x[$$0]++ { print("/home/lab5/hellomod/"$$0) }' > /home/lab5/hellomod/hellomod.mod
