#include "woodpacker.h"

Elf64_Shdr *search_oep_section_header(Elf64_Shdr *shdr, \
			uint64_t oep, uint64_t shnum)
{
	Elf64_Shdr *oep_shdr;
	uint64_t section_addr;
	uint64_t section_size;
	int index;

	oep_shdr = NULL;
	index = 0;
	printf("search oep include section header\n");
	while (index < shnum)
	{
		section_addr = shdr->sh_addr;
		section_size = shdr->sh_size;

		printf("addr:0x%016x size:0x%016x, oep:0x%016x\n", section_addr, section_size, oep);
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

Elf64_Phdr	*search_oep_segment_header(Elf64_Phdr *phdr, \
				uint64_t oep, uint64_t phnum)
{
	Elf64_Phdr *oep_phdr;
	uint64_t segment_vaddr;
	uint64_t segment_vsize;
	int index;

	oep_phdr = NULL;
	index = 0;
	printf("search oep include segment header\n");
	while (index < phnum)
	{
		segment_vaddr = phdr->p_vaddr;
		segment_vsize = phdr->p_memsz;
		printf("addr:0x%016x size:0x%016x, oep:0x%016x\n", segment_vaddr, segment_vsize, oep);
		if (segment_vaddr <= oep && \
			oep < segment_vaddr + segment_vsize)
		{
			printf("[%d]:\t", index);
			printf("oep segment found!\n");
			printf("0x%016x\n", phdr);
			oep_phdr = phdr;
			break ;
		}
		index++;
		phdr++;
	}
	return oep_phdr;

}

unsigned char decode_stub[] = {
  0x56, 0x51, 0x50, 0x48, 0xbe, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xff, 0xb9, 0x01, 0x00, 0x00, 0x00, 0xb0, 0xff,
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

    memcpy(&decode_stub[decode_start_offset], &code_vaddr, sizeof(DWORD));
    memcpy(&decode_stub[decode_size_offset],  &code_vsize, sizeof(DWORD));
    memcpy(&decode_stub[decoder_offset],  &decoder, sizeof(unsigned char));
    memcpy(&decode_stub[jmp_oep_addr_offset],  &jmp_len_to_oep, sizeof(DWORD));

    return;

}

void		handle_elf64(void *mmap_ptr)
{
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *oep_shdr;
	Elf64_Phdr *oep_phdr;

	ehdr = (Elf64_Ehdr *)mmap_ptr;
	shdr = (Elf64_Shdr *)((mmap_ptr + ehdr->e_shoff));
	phdr = (Elf64_Phdr *)((mmap_ptr + ehdr->e_phoff));
	oep_shdr = search_oep_section_header(shdr, ehdr->e_entry, ehdr->e_shnum);
	oep_phdr = search_oep_segment_header(phdr, ehdr->e_entry, ehdr->e_phnum);

	unsigned char encoder = 0xFF;
	xor_encoder((unsigned char *)(oep_shdr->sh_offset + target_bin_buffer), oep_shdr->sh_size, encoder);	

}
