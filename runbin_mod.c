/*************************************************************************************
*  Author: Stephanie Archibald <sarchibald@cylance.com>                              *
*  Copyright (c) 2017 Cylance Inc. All rights reserved.                              *
*                                                                                    *
*  Redistribution and use in source and binary forms, with or without modification,  *
*  are permitted provided that the following conditions are met:                     *
*                                                                                    *
*  1. Redistributions of source code must retain the above copyright notice, this    *
*  list of conditions and the following disclaimer.                                  *
*                                                                                    *
*  2. Redistributions in binary form must reproduce the above copyright notice,      *
*  this list of conditions and the following disclaimer in the documentation and/or  *
*  other materials provided with the distribution.                                   *
*                                                                                    *
*  3. Neither the name of the copyright holder nor the names of its contributors     *
*  may be used to endorse or promote products derived from this software without     *
*  specific prior written permission.                                                *
*                                                                                    *
*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND   *
*  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED     *
*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE            *
*  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR  *
*  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES    *
*  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;      *
*  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON    *
*  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT           *
*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS     *
*  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                      *
*                                                                                    *
*************************************************************************************/

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
