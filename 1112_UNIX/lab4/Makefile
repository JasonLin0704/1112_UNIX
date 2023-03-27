all: s r p

s: solver.c
	gcc solver.c -o solver -fstack-protector
	objdump -D solver -M intel > solver.s

r: remoteguess.c
	gcc remoteguess.c -o remoteguess -fstack-protector
	objdump -D remoteguess -M intel > remoteguess.s

p: submit.py
	python3 submit.py