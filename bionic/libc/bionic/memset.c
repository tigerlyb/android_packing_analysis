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
#include <string.h>
#include <stdint.h>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#define APPLICATION_UID 10000
extern void*  __memset(void *, int, size_t);

/*
unsigned long memset_addr_array[MEMSET_ARRAY_SIZE] = {0};
size_t memset_n_array[MEMSET_ARRAY_SIZE] = {0};
unsigned long memset_checksum_array[MEMSET_ARRAY_SIZE] = {0};
*/

int __trace_id = 100000;
char __pkg_name[100] = {0};
char __method_name[100] = {0};

//char __write_data_m[128] = {0};

char log_path[100] = {0};
char memset_path[100] = {0};
char memcpy_path[100] = {0};
char free_path[100] = {0};

/*
char index_path[100] = {0};

int memsetIndex = 0;
char dstaddr[16] = {0};

int reset_array() 
{
    memsetIndex = 0;

    for (int i = 0; i < MEMSET_ARRAY_SIZE; i++) {
        memset_addr_array[i] = 0;
        memset_n_array[i] = 0;
        memset_checksum_array[i] = 0;
    }

    return memsetIndex;
}
*/

int set_trace_id(int trace_id)
{
    
    if (trace_id < APPLICATION_UID) {
        return 0;
    }

    __trace_id = trace_id;

    return 1;
}

int get_trace_id()
{
    return __trace_id;
}

int set_pkg_name(char* pkg_name, char* id_string)
{
    if (pkg_name == NULL) {
        return 0;
    }

    strcpy(__pkg_name, "/data/data/");
    strcat(__pkg_name, pkg_name);
    strcat(__pkg_name, "/pid");

    strcpy(log_path, __pkg_name);
    strcat(log_path, id_string);
    strcat(log_path, "log.ltrace");

    strcpy(memset_path, __pkg_name);
    strcat(memset_path, id_string);
    strcat(memset_path, ".memset");

    strcpy(memcpy_path, __pkg_name);
    strcat(memcpy_path, id_string);
    strcat(memcpy_path, ".memcpy");

    strcpy(free_path, __pkg_name);
    strcat(free_path, id_string);
    strcat(free_path, ".free");

    /*
    strcpy(index_path, __pkg_name);
    strcat(index_path, id_string);
    strcat(index_path, ".keymemset");
    */

    return 1;
}

int set_method_name(const char* method_name)
{
    if (method_name == NULL) {
        return 0;
    }

    strcpy(__method_name, method_name);

    return 1;
}

int reset_method_name()
{

    for (int i = 0; i < sizeof(__method_name); i++) {
        __method_name[i] = 0;
    }

    return (int) __method_name[0];
}

unsigned long atonum(char* addr) {
    int len = strlen(addr);

    unsigned long result = 0;
    int i;
    for (i = 0; i < len; i++) {
        int index = addr[i];
        if (index >= '0' && index <= '9')
            result = result * 16 + (index - '0');

        if (index >= 'a' && index <= 'f')
            result = result * 16 + (index - 'W');
    }

    return result;
}

void*  memset(void* dst, int c, size_t n)
{

    int trace_id = getuid();

    if (trace_id == __trace_id && __method_name[0] != 0) {
                   
        int fd = __open(memset_path, O_RDWR | O_APPEND | O_CREAT, 0644);

        if (fd > 0) {
            /*
            if (memsetIndex < MEMSET_ARRAY_SIZE) {                
                
                sprintf(dstaddr, "%p", dst);
                memset_addr_array[memsetIndex] = atonum(dstaddr);
                memset_n_array[memsetIndex] = n;
                
                unsigned long checksum = 0;
                
                for (int i = 0; i < (int) n; i++) {
                    checksum = checksum + c + 1;
                }
                
                memset_checksum_array[memsetIndex] = checksum;
                snprintf(__write_data_m, sizeof(__write_data_m), "[method=%s, index=%d, checksum=%ld, dst=%p, size=%d]:\n", __method_name, memsetIndex, checksum, dst, n);
                write(fd, __write_data_m, strlen(__write_data_m));
            } else {
                snprintf(__write_data_m, sizeof(__write_data_m), "[method=%s, dst=%p, size=%d]:\n", __method_name, dst, n);
                write(fd, __write_data_m, strlen(__write_data_m));
            }
            */
            write(fd, "[", 1);
            write(fd, __method_name, strlen(__method_name));
            write(fd, "]:", 2);

            char* d = dst;            
            write(fd, d, n);
            write(fd, "\n", 1);
        }

        close(fd);
        //memsetIndex++;
    }
    
	__memset(dst, c, n);

    return dst;

	/*
    char*  q   = dst;
    char*  end = q + n;

    for (;;) {
        if (q >= end) break; *q++ = (char) c;
        if (q >= end) break; *q++ = (char) c;
        if (q >= end) break; *q++ = (char) c;
        if (q >= end) break; *q++ = (char) c;
    }

  	//return dst;
  	*/

}