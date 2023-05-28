fs = rootfs.cpio.bz2
nfs = newrootfs.cpio.bz2

all: k p s

s:
	python3 submit.py kshram/kshram.ko
q:
	./qemu.sh
# u:
# 	cd dist && \
# 	bzip2 -dc rootfs.cpio.bz2 | cpio -id -D ./newrootfs
p:
	cd ./dist/newrootfs && \
	if [ -f $(nfs) ]; then rm $(nfs); fi; \
	find . | cpio -H newc -o | bzip2 > ../newrootfs.cpio.bz2
k:
	cd ./kshram && $(MAKE); \
	cp kshram.ko ../dist/newrootfs/kshram
