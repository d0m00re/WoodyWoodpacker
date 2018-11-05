#ifndef WOODPACKER_H
#define WOOD_PACHER_H

#include <elf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

void	handle_elf64(void *mmap_ptr, size_t original_filesize);
void	handle_error(char *str);
void xor_encoder(unsigned char *start, unsigned int size, unsigned char encoder);

#endif
