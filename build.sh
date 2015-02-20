javac src/java/wwk/Xattrj.java -d target/classes
javah -cp target/classes -d src/c wwk.Xattrj
cc -c -fPIC -m64 -I/mnt/E_SOFT/Soft/Ubuntu/jdk1.7.0_71/include -I/mnt/E_SOFT/Soft/Ubuntu/jdk1.7.0_71/include/linux src/c/wwk_Xattrj.c
cc -shared -fPIC wwk_Xattrj.o -o libwwkxattr.so
