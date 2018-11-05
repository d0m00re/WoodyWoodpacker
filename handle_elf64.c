#include "woodpacker.h"

#include <string.h>

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

Elf64_Shdr *search_oep_section_header64(Elf64_Shdr *shdr, \
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
			break ;
		}
		index++;
		shdr++;
	}
	return oep_shdr;
}

Elf64_Shdr		*add_new_section_header64(void *map, Elf64_Shdr *shdr, uint64_t shnum, size_t filesize)
{
	int 		index;
	int		added;
	Elf64_Shdr	*prev_shdr;
	Elf64_Shdr	*new_shdr;

	index = 0;
	added = 0;
	printf("[+] search oep include section header\n");
	while (index < shnum + 1)
	{
/*
		printf("[%d] sh_name:0x%016lx sh_type:0x%016lx, sh_flags:0x%016lx ", index, shdr->sh_name, shdr->sh_type, shdr->sh_flags);
		printf("sh_addr:0x%016lx sh_offset:0x%016lx, sh_size:0x%016lx ", shdr->sh_addr, shdr->sh_offset, shdr->sh_size);
		printf("sh_link:0x%016lx sh_addralign:0x%016lx ", shdr->sh_link, shdr->sh_addralign);
		printf("sh_entsize:0x%016lx\n", shdr->sh_entsize);
*/
		/* if the section is added then we need to shift the sh_offset of other consecutive section after our section */
		if (added)
		{
			shdr->sh_offset += sizeof(decode_stub);
		}
		if (index != 0 && shdr->sh_addr == 0 && added == 0)
		{
			//prev_shdr = (void *)shdr - sizeof(Elf64_Shdr);
			printf(" !!!!! [%d]\n", index);
			/* shift the memory to create a new space for our section hedaer */
			memmove((void *)shdr + sizeof(Elf64_Shdr), (void *)shdr, filesize - ((size_t)shdr - (size_t)map));
			/* Initialize our section header */
			shdr->sh_name = 0x0;
			shdr->sh_type = SHT_PROGBITS;
			shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
			shdr->sh_addr = prev_shdr->sh_addr + prev_shdr->sh_size;
			shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
			shdr->sh_size = sizeof(decode_stub);
			shdr->sh_link = 0x0;
			shdr->sh_addralign = 0x10;
			shdr->sh_entsize = 0x0;
			added = 1;
			new_shdr = shdr;
		}
		prev_shdr = shdr;
		index++;
		shdr++;
	}
	return (new_shdr);
}

Elf64_Phdr	*search_oep_segment_header64(Elf64_Phdr *phdr, \
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
/*
		printf("[%d] p_type:0x%016lx p_offset:0x%016lx, p_vaddr:0x%016lx ", index, phdr->p_type, phdr->p_offset, phdr->p_vaddr);
		printf("p_paddr:0x%016lx p_filesz:0x%016lx, p_memsz:0x%016lx ", phdr->p_paddr, phdr->p_filesz, phdr->p_memsz);
		printf("p_flags:0x%016lx p_align:0x%016lx\n", phdr->p_flags, phdr->p_align);
*/
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

void		modify_program_header64(Elf64_Phdr *phdr, uint64_t phnum)
{
	int index;

	index = 0;
	while (index < phnum)
	{
		//printf("addr:0x%016lx size:0x%016lx, oep:0x%016lx\n", segment_vaddr, segment_vsize, oep);
/*
		printf("[%d] p_type:0x%016lx p_offset:0x%016lx, p_vaddr:0x%016lx ", index, phdr->p_type, phdr->p_offset, phdr->p_vaddr);
		printf("p_paddr:0x%016lx p_filesz:0x%016lx, p_memsz:0x%016lx ", phdr->p_paddr, phdr->p_filesz, phdr->p_memsz);
		printf("p_flags:0x%016lx p_align:0x%016lx\n", phdr->p_flags, phdr->p_align);
*/
		if (phdr->p_type == PT_LOAD)
		{
			phdr->p_flags = PF_X | PF_W | PF_R;
			if (phdr->p_offset != 0)
			{
				phdr->p_filesz += sizeof(decode_stub);
				phdr->p_memsz += sizeof(decode_stub);
			}
		}
		index++;
		phdr++;
	}
}


void create_decode_stub(uint64_t code_vaddr, uint64_t code_vsize,
		unsigned char decoder, uint64_t oep)
{
	int    cnt=0;
	int    jmp_len_to_oep=0;

//	jmp_len_to_oep = oep - (code_vaddr + code_vsize + sizeof(decode_stub));
	jmp_len_to_oep = 0xffffffff;
	printf("start   : 0x%16X\n", code_vaddr);
	printf("size    : 0x%16X\n", code_vsize);
	printf("decoder : 0x%02X\n", decoder);
	printf("oep     : 0x%16X\n", oep);
	printf("jmp len : 0x%16X\n", jmp_len_to_oep);
	memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(long));
	memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(int));
	memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(unsigned char));
	//memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(long));

	printf("Modified stub!\n");
	return;

}

void		handle_elf64(void *mmap_ptr, size_t original_filesize)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *oep_shdr;
	Elf64_Shdr *new_shdr;
	Elf64_Phdr *oep_phdr;
	void *map;
	int fd;

	if ((fd = open("woody", O_RDWR | O_CREAT, (mode_t)0755)) < 0)
		handle_error("Can not create the executable woody.\n");
	size_t size = original_filesize + sizeof(decode_stub) + sizeof(Elf64_Shdr);
	printf("decode_stub:%x\t | original_filesize:%x\n", sizeof(decode_stub), original_filesize);
	if ((map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		handle_error("Can not map te file!\n");
	printf("%x | %x | %x\n", (void *)map, (void *)mmap_ptr, size);
	memcpy(map, mmap_ptr, original_filesize);
	
	ehdr = (Elf64_Ehdr *)map;
	shdr = (Elf64_Shdr *)((map + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((map + ehdr->e_phoff));

	/* get section header of 'text' */
/*
	printf("BEFORE===== size:%zu\n", oep_shdr->sh_size);
	for (int i = 0; i< oep_shdr->sh_size;i++)
		printf("%02x-", *(unsigned char *)(oep_shdr->sh_offset + (void *)map + i));
	printf("\n");
*/
	/* add section 'anonymous' */
	new_shdr = add_new_section_header64(map, shdr, ehdr->e_shnum, original_filesize);
/*
	printf("AFTER===== size:%zu\n", oep_shdr->sh_size);
	for (int i = 0; i< oep_shdr->sh_size;i++)
		printf("%02x-", *(unsigned char *)(oep_shdr->sh_offset + (void *)map + i));
	printf("\n");
*/

	/* add 1 to the header  */
	ehdr->e_shnum += 1;
	printf("=========\n");
	search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum);
	printf("---------\n");

/*
	oep_phdr = search_oep_segment_header64(phdr, ehdr->e_entry, ehdr->e_phnum);
	if (oep_phdr == NULL)
		handle_error("No entry point section found.\n");
*/

	oep_shdr = search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum);
	if (oep_shdr == NULL)
		handle_error("No entry point section found.\n");



	/* Encode .text */
	unsigned char encoder = 0xbb;

	printf("oep_shdr->sh_offset:%lx\n", oep_shdr->sh_offset);
	xor_encoder((unsigned char *)(oep_shdr->sh_offset + map), oep_shdr->sh_size, encoder);
/*
	for (int i =0; i< sizeof(decode_stub);i++)
		printf("%02x-", decode_stub[i]);
	printf("\n");
*/

	create_decode_stub(oep_shdr->sh_addr, oep_shdr->sh_size, encoder, ehdr->e_entry);

	/* modify program header */
	modify_program_header64(phdr, ehdr->e_phnum);
	printf("[+] Modified program header!\n");
	//exit(0);
/*
	for (int i =0; i< sizeof(decode_stub);i++)
		printf("%02x-", decode_stub[i]);
	printf("\n");
*/
	printf("[*] Previous entry point:%lx\n", ehdr->e_entry);
	ehdr->e_entry = new_shdr->sh_addr;
	printf("[+] Modified Entry point to :%lx!\n", ehdr->e_entry);

	memmove((void *)(map + new_shdr->sh_offset + new_shdr->sh_size), (void *)(map + new_shdr->sh_offset), size - new_shdr->sh_offset);


	/* section header start from + sizeof(decode_stub) */
	ehdr->e_shoff += sizeof(decode_stub);
	shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	new_shdr = search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum);
	printf("[+] Moved the memory to give a free space to place decode_stub!\n");
	printf("%p %p %zu\n", new_shdr->sh_offset, decode_stub, sizeof(decode_stub));
	memcpy((void *)(map + new_shdr->sh_offset), decode_stub, sizeof(decode_stub));
	printf("[+] Copied the decode_stub inside the binary!\n");
	write(fd, map, size);
	printf("[+] Finished writing to woody!\n");
	munmap(map, size);
	close(fd);
}
