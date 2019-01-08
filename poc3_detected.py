#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import requests
if '__main__' == __name__:
  # get the dylib from remote server
  r = requests.get("http://2016.eicar.org/download/eicar.com")
  r.raise_for_status()
  f = open("/tmp/eicsar.com", "wb")
  f.write(bytes(r.content))
  f.seek(0)
  f.close()
