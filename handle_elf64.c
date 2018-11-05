#include "woodpacker.h"

#include <string.h>

Elf64_Shdr *search_oep_section_header(Elf64_Shdr *shdr, \
		uint64_t oep, uint64_t shnum)
{
	Elf64_Shdr *oep_shdr;
	uint64_t section_addr;
	uint64_t section_size;
	int index;

	oep_shdr = NULL;
	index = 0;
	printf("[+] search oep include section header\n");
	while (index < shnum)
	{
		section_addr = shdr->sh_addr;
		section_size = shdr->sh_size;

		//printf("addr:0x%016lx size:0x%016lx, oep:0x%016lx\n", section_addr, section_size, oep);
		printf("[%d] sh_name:0x%016lx sh_type:0x%016lx, sh_flags:0x%016lx ", index, shdr->sh_name, shdr->sh_type, shdr->sh_flags);
		printf("sh_addr:0x%016lx sh_offset:0x%016lx, sh_size:0x%016lx ", shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
		printf("sh_link:0x%016lx sh_addralign:0x%016lx ", shdr->sh_link, shdr->sh_addralign);
		printf("sh_entsize:0x%016lx\n", shdr->sh_entsize);

		if (section_addr <= oep && oep < section_addr + section_size)
		{
			printf("[%d]:\t", index);
			printf("oep section found!\n");
			printf("0x%016x\n", shdr);
			oep_shdr = shdr;
			//break ;
		}
		index++;
		shdr++;
	}
	return oep_shdr;
}

Elf64_Phdr	*search_oep_segment_header(Elf64_Phdr *phdr, \
		uint64_t oep, uint64_t phnum)
{
	Elf64_Phdr *oep_phdr;
	uint64_t segment_vaddr;
	uint64_t segment_vsize;
	int index;

	oep_phdr = NULL;
	index = 0;
	printf("[+] search oep include segment header\n");
	while (index < phnum)
	{
		segment_vaddr = phdr->p_vaddr;
		segment_vsize = phdr->p_memsz;
		//printf("addr:0x%016lx size:0x%016lx, oep:0x%016lx\n", segment_vaddr, segment_vsize, oep);
		printf("[%d] p_type:0x%016lx p_offset:0x%016lx, p_vaddr:0x%016lx ", index, phdr->p_type, phdr->p_offset, phdr->p_vaddr);
		printf("p_paddr:0x%016lx p_filesz:0x%016lx, p_memsz:0x%016lx ", phdr->p_paddr, phdr->p_filesz, phdr->p_memsz);
		printf("p_flags:0x%016lx p_align:0x%016lx\n", phdr->p_flags, phdr->p_align);
		if (segment_vaddr <= oep && \
				oep < segment_vaddr + segment_vsize)
		{
			printf("[%d]:\t", index);
			printf("oep segment found!\n");
			printf("0x%016x\n", phdr);
			oep_phdr = phdr;
			//break ;
		}
		index++;
		phdr++;
	}
	return oep_phdr;

}

unsigned char decode_stub[] = {
	0x56, 0x51, 0x50, 0x48, 0xbe, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0xb9, 0xde, 0xad, 0xbe, 0xef, 0xb0, 0xff,
	0x30, 0x06, 0x48, 0xff, 0xc6, 0xff, 0xc9, 0x75, 0xf7, 0x58,
	0x59, 0x5e, 0x48, 0xb8, 0x00, 0xc0, 0xfd, 0x23, 0x07, 0x7f,
	0x00, 0x00, 0xff, 0xe0,
};

unsigned int decode_start_offset = 5;
unsigned int decode_size_offset  = 14;
unsigned int decoder_offset      = 19;
unsigned int jmp_oep_addr_offset = 34;


void create_decode_stub(uint64_t code_vaddr, uint64_t code_vsize,
		unsigned char decoder, uint64_t oep)
{
	int    cnt=0;
	int    jmp_len_to_oep=0;

	jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));

	printf("start   : 0x%16X\n", code_vaddr);
	printf("size    : 0x%16X\n", code_vsize);
	printf("decoder : 0x%02X\n", decoder);
	printf("oep     : 0x%16X\n", oep);
	printf("jmp len : 0x%16X\n", jmp_len_to_oep);
	memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(long));
	memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(int));
	memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(unsigned char));
	memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(long));

	printf("Modified stub!\n");
	return;

}

void		handle_elf64(void *mmap_ptr, size_t original_filesize)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *oep_shdr;
	Elf64_Phdr *oep_phdr;
	void *map;
	int fd;

	if ((fd = open("woody", O_RDWR | O_CREAT, (mode_t)0755)) < 0)
		handle_error("Can not create the executable woody.\n");
	size_t size = sizeof(decode_stub) + original_filesize;
	printf("decode_stub:%x\t | original_filesize:%x\n", sizeof(decode_stub), original_filesize);
	if ((map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		handle_error("Can not map te file!\n");
	printf("%x | %x | %x\n", (void *)map, (void *)mmap_ptr, size);
	memcpy(map, mmap_ptr, original_filesize);
	
	ehdr = (Elf64_Ehdr *)map;
	shdr = (Elf64_Shdr *)((map + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((map + ehdr->e_phoff));
	oep_shdr = search_oep_section_header(shdr, ehdr->e_entry, ehdr->e_shnum);
	if (oep_shdr == NULL)
		handle_error("No entry point section found.\n");
	oep_phdr = search_oep_segment_header(phdr, ehdr->e_entry, ehdr->e_phnum);
	if (oep_phdr == NULL)
		handle_error("No entry point section found.\n");
	unsigned char encoder = 0xbb;

	xor_encoder((unsigned char *)(oep_shdr->sh_offset + map), oep_shdr->sh_size, encoder);
/*
	for (int i =0; i< sizeof(decode_stub);i++)
		printf("%02x-", decode_stub[i]);
	printf("\n");
*/
	create_decode_stub(oep_shdr->sh_addr, oep_shdr->sh_size, encoder, ehdr->e_entry);
/*
	for (int i =0; i< sizeof(decode_stub);i++)
		printf("%02x-", decode_stub[i]);
	printf("\n");
*/
	ehdr->e_entry = oep_shdr->sh_addr + oep_shdr->sh_size;
	oep_phdr->p_flags |= PF_W;
	memmove(oep_shdr->sh_offset + oep_shdr->sh_size + (void *)map + sizeof(decode_stub), oep_shdr->sh_offset + oep_shdr->sh_size + (void *)mmap_ptr, sizeof(decode_stub));
	memcpy(oep_shdr->sh_offset + oep_shdr->sh_size + (void *)map, decode_stub, sizeof(decode_stub));
	write(fd, map, size);
	munmap(map, size);
	close(fd);
}
