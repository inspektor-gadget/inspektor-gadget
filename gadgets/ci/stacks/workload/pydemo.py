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

def eat_apple():
    for _ in range(2):
        ptr = mylib.allocate_memory(64)

def eat_banana():
    for _ in range(2):
        ptr = mylib.allocate_memory(512)

def eat_orange():
    for _ in range(2):
        ptr = mylib.allocate_memory(1024)

def pick_up_fruits():
    eat_apple()
    eat_banana()
    eat_orange()
    mylib.sleep_one_second()
    mylib.sleep_one_second()
    sys.exit(0)

def my_garden():
    pick_up_fruits()
    pick_up_fruits()


def main():
    mylib.print_hello_world()
    ptr = mylib.allocate_memory(8)
    mylib.sleep_one_second()
    mylib.sleep_one_second()
    mylib.busy_loop_500ms()

    my_garden()
    time.sleep(1)

if __name__ == "__main__":
    main()

