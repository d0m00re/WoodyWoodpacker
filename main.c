#include "woodpacker.h"

void	handle_error(char *msg)
{
	dprintf(2, msg);
	exit(EXIT_FAILURE);
}

int	main(int argc, char **argv)
{
	int fd;
	void *mmap_ptr;
	off_t filesize;
	Elf64_Ehdr *header;

	if (argc != 2)
		handle_error("Usage : ./woody_woodpacker <file>\n");
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		handle_error("Can not open the file.\n");
	filesize =lseek(fd, (size_t)0, SEEK_END);
	if ((mmap_ptr = mmap(0, filesize, PROT_READ, MAP_PRIVATE, fd, 0))\
			== MAP_FAILED)
		handle_error("Can not map the file.\n");
	if (filesize < sizeof(Elf64_Ehdr))
		handle_error("The size of the file is too small.\n");
	header = (Elf64_Ehdr *)mmap_ptr;
	printf("%x:%c%c%c\n", header->e_type, header->e_ident[1], header->e_ident[2], header->e_ident[3]);
	if(header->e_type & (0x2 | 0x3) &&
			header->e_ident[1] == 'E' &&
			header->e_ident[2] == 'L' &&
			header->e_ident[3] == 'F') {
		printf("ELF Executable!\n");
		if (header->e_ident[EI_CLASS] == 1)
			printf("32 bits!\n");
		else if (header->e_ident[EI_CLASS] == 2)
		{
			printf("64 bits!\n");
			handle_elf64(mmap_ptr, filesize);
		}
		else
			handle_error("Undefined EI_CLASS value.\n");
	}
	else
		handle_error("the file is not an Elf executable.\n");
	if ((close(fd)) < 0)
		handle_error("Can not close the file.\n");
	if ((munmap(mmap_ptr, filesize)) < 0)
		handle_error("Can not munmap the memory.\n");
	return (0);
}
