gcc -o mylib.o -c my.c
gcc -shared -o libmylib.so  mylib.o

# LD_LIBRARY_PATH adjusted, no need for cp libmylib.so /usr/local/bin/

nginx -p `pwd`/ -c nginx.conf
