all:cc
cc:
	@g++ sdb.cpp -o sdb -lcapstone ptools.cpp
g: cc
	@./sdb ./guess
h: cc
	@./sdb ./hello
h64: cc
	@./sdb ./hello64
hh: cc
	@./sdb ./hw2_testcases/hello
hl: cc
	@./sdb ./hw2_testcases/loop1
hd: cc
	@./sdb ./hw2_testcases/deep