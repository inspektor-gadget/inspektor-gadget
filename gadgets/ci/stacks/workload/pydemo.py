#!/usr/bin/python3

import ctypes
import os
import sys
import time

script_dir = os.path.dirname(os.path.abspath(__file__))
lib_path = os.path.join(script_dir, "libmylib.so")

mylib = ctypes.CDLL(lib_path)

mylib.allocate_memory.argtypes = [ctypes.c_size_t]
mylib.allocate_memory.restype = ctypes.c_void_p

def level3():
    for _ in range(50):
        mylib.print_hello_world()
        mylib.sleep_one_second()
        mylib.busy_loop_500ms()
        ptr = mylib.allocate_memory(1024)

    sys.exit(0)

def level2():
    level3()
    level3()

def level1():
    level2()
    level2()


def main():
    level1()
    time.sleep(1)

if __name__ == "__main__":
    main()

