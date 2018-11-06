#include "woodpacker.h"

void	handle_error(char *msg)
{
	dprintf(2, msg);
	exit(EXIT_FAILURE);
}

void	print_default_error(void)
{
	perror("[-] Error : ");
	exit(EXIT_FAILURE);
}


static void	check_header(void *mmap_ptr, size_t filesize)
{
	Elf64_Ehdr *header;

	header = (Elf64_Ehdr *)mmap_ptr;
	printf("[*] %x:%c%c%c\n", header->e_type, header->e_ident[1], header->e_ident[2], header->e_ident[3]);
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
		{
			if ((munmap(mmap_ptr, filesize)) < 0)
				print_default_error();
			handle_error("Undefined EI_CLASS value.\n");
		}
	}
	else
	{
		if ((munmap(mmap_ptr, filesize)) < 0)
			print_default_error();
		handle_error("the file is not an Elf executable.\n");
	}
}

int	main(int argc, char **argv)
{
	int fd;
	void *mmap_ptr;
	off_t filesize;

	if (argc != 2)
		handle_error("Usage : ./woody_woodpacker <file>\n");
	if ((fd = open(argv[1], O_RDONLY)) < 0)
		print_default_error();
	filesize =lseek(fd, (size_t)0, SEEK_END);
	if ((mmap_ptr = mmap(0, filesize, PROT_READ, MAP_PRIVATE, fd, 0))\
			== MAP_FAILED)
		print_default_error();
	if (filesize < sizeof(Elf64_Ehdr))
		handle_error("The size of the file is too small.\n");
	check_header(mmap_ptr, filesize);
	if ((close(fd)) < 0)
		print_default_error();
	if ((munmap(mmap_ptr, filesize)) < 0)
		print_default_error();
	return (EXIT_SUCCESS);
}
