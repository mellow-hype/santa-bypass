#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import requests, ctypes
if '__main__' == __name__:
  r = requests.get("http://localhost:8080/rlm.dylib")
  r.raise_for_status()
  f = open("/tmp/lib", "wb")
  f.write(bytes(r.content))
  f.seek(0)
  mylib = ctypes.cdll.loadlibrary(f.name)
  mylib.launch("/bin/cp")
