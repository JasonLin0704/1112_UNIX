all: r
r:
	gcc runner.c -o runner -static-pie
s: r
	python3 submit.py ./runner
1: r
	./runner ./sample1
2: r
	./runner ./sample2
3: r
	./runner ./sample3