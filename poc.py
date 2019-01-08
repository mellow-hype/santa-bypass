#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import ctypes
if '__main__' == __name__:
  mylib = ctypes.cdll.LoadLibrary("rlm.dylib")
  mylib.launch("/bin/cp")

