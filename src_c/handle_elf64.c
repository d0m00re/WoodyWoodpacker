#include "../woodpacker.h"

# define DECODE_SIZE 334

unsigned char		decode_stub[DECODE_SIZE + KEY_MAXLEN] = {
  0x9c, 0x50, 0x57, 0x56, 0x54, 0x52, 0x51, 0x41, 0x50, 0x41,
  0x51, 0x41, 0x52, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x1d,
  0x01, 0x00, 0x00, 0x5e, 0xba, 0x10, 0x00, 0x00, 0x00, 0x48,
  0x89, 0xf8, 0x0f, 0x05, 0xe9, 0x22, 0x01, 0x00, 0x00, 0x5f,
  0xbe, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0xcb, 0xff,
  0xff, 0xff, 0xb9, 0x01, 0x00, 0x00, 0x00, 0x48, 0x81, 0xec,
  0x88, 0x01, 0x00, 0x00, 0x49, 0x89, 0xd1, 0x41, 0xb8, 0x00,
  0x00, 0x00, 0x00, 0x46, 0x88, 0x84, 0x04, 0x88, 0x00, 0x00,
  0x00, 0x44, 0x89, 0xc0, 0x99, 0xf7, 0xfe, 0x48, 0x63, 0xd2,
  0x0f, 0xb6, 0x04, 0x17, 0x42, 0x88, 0x44, 0x04, 0x88, 0x49,
  0x83, 0xc0, 0x01, 0x49, 0x81, 0xf8, 0x00, 0x01, 0x00, 0x00,
  0x75, 0xd9, 0xba, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00,
  0x00, 0x00, 0x4c, 0x8d, 0x44, 0x24, 0x88, 0x0f, 0xb6, 0xbc,
  0x14, 0x88, 0x00, 0x00, 0x00, 0x40, 0x0f, 0xb6, 0xc7, 0x01,
  0xf0, 0x42, 0x0f, 0xb6, 0x34, 0x02, 0x01, 0xf0, 0x89, 0xc6,
  0xc1, 0xfe, 0x1f, 0xc1, 0xee, 0x18, 0x01, 0xf0, 0x0f, 0xb6,
  0xc0, 0x29, 0xf0, 0x89, 0xc6, 0x48, 0x98, 0x44, 0x0f, 0xb6,
  0x94, 0x04, 0x88, 0x00, 0x00, 0x00, 0x44, 0x88, 0x94, 0x14,
  0x88, 0x00, 0x00, 0x00, 0x40, 0x88, 0xbc, 0x04, 0x88, 0x00,
  0x00, 0x00, 0x48, 0x83, 0xc2, 0x01, 0x48, 0x81, 0xfa, 0x00,
  0x01, 0x00, 0x00, 0x75, 0xb2, 0x85, 0xc9, 0x7e, 0x4a, 0x8d,
  0x41, 0xff, 0x49, 0x8d, 0x7c, 0x01, 0x01, 0x31, 0xd2, 0x31,
  0xc0, 0x48, 0x83, 0xc0, 0x01, 0x0f, 0xb6, 0xc0, 0x0f, 0xb6,
  0x8c, 0x04, 0x88, 0x00, 0x00, 0x00, 0x01, 0xca, 0x0f, 0xb6,
  0xd2, 0x0f, 0xb6, 0xb4, 0x14, 0x88, 0x00, 0x00, 0x00, 0x40,
  0x88, 0xb4, 0x04, 0x88, 0x00, 0x00, 0x00, 0x88, 0x8c, 0x14,
  0x88, 0x00, 0x00, 0x00, 0x02, 0x8c, 0x04, 0x88, 0x00, 0x00,
  0x00, 0x41, 0x30, 0x09, 0x49, 0x83, 0xc1, 0x01, 0x4c, 0x39,
  0xcf, 0x75, 0xc2, 0x48, 0x81, 0xc4, 0x88, 0x01, 0x00, 0x00,
  0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x59, 0x5a, 0x5c, 0x5e,
  0x5f, 0x58, 0x9d, 0xe9, 0xdc, 0x03, 0x40, 0x00, 0xe8, 0xde,
  0xfe, 0xff, 0xff, 0x2e, 0x2e, 0x2e, 0x2e, 0x57, 0x4f, 0x4f,
  0x44, 0x59, 0x2e, 0x2e, 0x2e, 0x2e, 0x2e, 0x0a, 0x00, 0xe8,
  0xd9, 0xfe, 0xff, 0xff
};

unsigned int 		key_addr_offset = DECODE_SIZE;
unsigned int 		key_size_offset = 41;
unsigned int 		decode_start_offset = 48;
unsigned int 		decode_size_offset  = 53;
unsigned int 		jmp_oep_addr_offset = 304;

Elf64_Shdr 		*search_oep_section_header64(Elf64_Shdr *shdr, \
		uint64_t oep, uint64_t shnum)
{
	Elf64_Shdr 	*oep_shdr;
	uint64_t 	section_addr;
	uint64_t 	section_size;
	unsigned int	index;

	oep_shdr = NULL;
	index = 0;
	while (index < shnum)
	{
		section_addr = shdr->sh_addr;
		section_size = shdr->sh_size;
		if (section_addr <= oep && oep < section_addr + section_size)
		{
			oep_shdr = shdr;
			break ;
		}
		index++;
		shdr++;
	}
	return oep_shdr;
}

Elf64_Shdr		*add_new_section_header64(void *map, Elf64_Shdr *shdr, \
						uint64_t shnum, size_t filesize)
{
	unsigned int 	index;
	int		added;
	Elf64_Shdr	*prev_shdr;
	Elf64_Shdr	*new_shdr;

	index = 0;
	added = 0;
	while (index < shnum + 1)
	{
		/* if the section is added then we need to shift the sh_offset of other consecutive section after our section */
		if (added)
			shdr->sh_offset += sizeof(decode_stub);
		if (index != 0 && shdr->sh_addr == 0 && added == 0)
		{
			/* shift the memory to create a new space for our section hedaer */
			ft_memmove((void *)shdr + sizeof(Elf64_Shdr), (void *)shdr, filesize - ((size_t)shdr - (size_t)map));
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

void			modify_program_header64(Elf64_Phdr *phdr, uint64_t phnum)
{
	unsigned int	index;

	index = 0;
	while (index < phnum)
	{
		if (phdr->p_type == PT_LOAD)
		{
			phdr->p_flags = PF_X | PF_W | PF_R;
			/* our new section is not added on the first LOAD so skip the first part */
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

void			create_decode_stub(uint64_t oep_old, uint64_t oep_new, uint64_t oep_old_size)
{
	int 		rsi_oep_old = oep_old - (oep_new + decode_start_offset) - 4;
 	int 		jmp_to_oep_old = oep_old - (oep_new + jmp_oep_addr_offset) - 4;
	int 		key_maxlen = KEY_MAXLEN;

	// first address of oep_old      oep_old - ( oep_new + decode_start_offset)
	ft_memcpy(&decode_stub[decode_start_offset], &rsi_oep_old, sizeof(int));
	// size
	ft_memcpy(&decode_stub[decode_size_offset],  &oep_old_size, sizeof(int));
	ft_memcpy(&decode_stub[key_size_offset],  &key_maxlen, sizeof(int));

	// the address of oep_old oep_old - ( oep_new + jmp_offset) 
	ft_memcpy(&decode_stub[jmp_oep_addr_offset], &jmp_to_oep_old, sizeof(int));
	
	/* check the new key size */
	if (sizeof(decode_stub) - key_addr_offset < sizeof(key))
		handle_error("The key is too big.\n");
	ft_memcpy(&decode_stub[key_addr_offset],  &key, sizeof(key));
	return;

}

void			handle_elf64(void *mmap_ptr, size_t original_filesize)
{
	Elf64_Ehdr 	*ehdr;
	Elf64_Shdr 	*shdr;
	Elf64_Phdr 	*phdr;
	Elf64_Shdr 	*oep_shdr;
	Elf64_Shdr 	*new_shdr;
	void 		*map;
	size_t 		size;

	size = original_filesize + DECODE_SIZE + sizeof(Elf64_Shdr);
	if ((map = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)) == MAP_FAILED)
		print_default_error();
	ft_memcpy(map, mmap_ptr, original_filesize);

	if ((munmap(mmap_ptr, original_filesize)) < 0)
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		print_default_error();
	}

	ehdr = (Elf64_Ehdr *)map;
	shdr = (Elf64_Shdr *)((map + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((map + ehdr->e_phoff));

	/* Verify if the size matches */
	if ((original_filesize - ehdr->e_shoff) < ehdr->e_shnum * sizeof(Elf64_Shdr))
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		handle_error("Filesize does not match with number of section header.\n");
	}

	/* add section 'anonymous' */
	new_shdr = add_new_section_header64(map, shdr, ehdr->e_shnum, original_filesize);

	/* add 1 to the header  */
	ehdr->e_shnum += 1;
	/* add 1 to the e_shstrndx because we added our new section before the strtab */
	ehdr->e_shstrndx += 1;


	/* Get section which contain entry point then Encrypt the section */
	oep_shdr = search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum);
	if (oep_shdr == NULL)
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		handle_error("No entry point section found.\n");
	}

	/* Check the size of the section */
	if (original_filesize < (oep_shdr->sh_offset + oep_shdr->sh_size))
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		handle_error("Filesize too small for entry point section to fit.\n");
	}

	/* encrypt the entry point section */
	rc4(key, sizeof(key), (char *)(oep_shdr->sh_offset + map), oep_shdr->sh_size);

	/* create decoder  */
	create_decode_stub(oep_shdr->sh_addr, new_shdr->sh_addr, oep_shdr->sh_size);

	/* Verify if the program header is inside the file */
	if ((original_filesize - ehdr->e_phoff) < ehdr->e_phnum * sizeof(Elf64_Phdr))
	{
		if ((munmap(map, size)) < 0)
			print_default_error();
		handle_error("Filesize does not match with number of program header.\n");
	}

	/* modify program header */
	modify_program_header64(phdr, ehdr->e_phnum);
	/* modify entry point */
	ehdr->e_entry = new_shdr->sh_addr;

	ft_memmove((void *)(map + new_shdr->sh_offset + new_shdr->sh_size), (void *)(map + new_shdr->sh_offset), size - new_shdr->sh_offset);

	/* section header start from + sizeof(decode_stub) */
	ehdr->e_shoff += sizeof(decode_stub);

	shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
	new_shdr = search_oep_section_header64(shdr, ehdr->e_entry, ehdr->e_shnum);

	/* copy the stub */

	ft_memcpy((void *)(map + new_shdr->sh_offset), decode_stub, sizeof(decode_stub));
	map_to_file(map, size);
	if ((munmap(map, size)) < 0)
		print_default_error();
}
