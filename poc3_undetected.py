#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import tempfile
import requests
 
if '__main__' == __name__:
  # get the dylib from remote server
  r = requests.get("http://2016.eicar.org/download/eicar.com")
  r.raise_for_status()
  # create a NamedTemporaryFile object to hold the dylib
  f = tempfile.NamedTemporaryFile(delete=True)
  f.write(bytes(r.content))
  f.seek(0)
  f.close()

 