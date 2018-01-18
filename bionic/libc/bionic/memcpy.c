/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
//#define MEMCOPY
//#include "bcopy.c"


#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

extern void*  __memcpy(void *, const void *, size_t);
//int memcpyIndex = 0; 


void*  memcpy(void* dst, const void* source, size_t n)
{

    
    int trace_id = getuid();
 
    if (trace_id == __trace_id && __method_name[0] != 0) {
        //memcpyIndex++; 
        /*
        int sfd = __open(log_path, O_RDWR | O_APPEND | O_CREAT, 0644);
        if (sfd > 0) {
            write(sfd, "calling memcpy\n", 15);
        }
        close(sfd);
        */
        
        int fd = __open(memcpy_path, O_RDWR | O_APPEND | O_CREAT, 0644);

        if (fd > 0) {
            write(fd, "[", 1);
            write(fd, __method_name, strlen(__method_name));
            write(fd, "]:", 2);

            char* s = source;
            write(fd, s, n);
            write(fd, "\n", 1);
        }

        close(fd);
    }

    
	return __memcpy(dst, source, n);
}