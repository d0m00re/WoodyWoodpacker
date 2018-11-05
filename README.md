# WoodyWoodpacker
Projet dans la suite logique de nm/otools qui a pour principe de modifier les headers d'un fichier de type ELF64. Le but ici est de pouvoir ajouter un morceau de code et obfusquer une partie d'un fichier non strippé.

## Comment faire

On va creer un program qui s'appelle packer qui va modifier le binaire en sorte que:

[Execution] -> [Execute .text]

[Execution] -> [decode the .text] -> [Execute .text]

le packer doit encrypter la partie .text et ajouter la partie decoder qui va decrypter au niveau de runtime.

D'abord On va creer notre propre section header qui va etre utile pour s'addresser a notre decoder de text.
le meilleur endroit pour ajouter notre propre section est juste avant les sections qui contient des sh_addr = 0x0 car on a pas besoin de modifier chaque offsets.

Donc:

[.bss] [.comment] [.shstrtab] [.symtab] [.strtab]

va etre

[.bss] __[decoder!]__ [.comment] [.shstrtab] [.symtab] [.strtab]

notre section decoder va contenir

```
  shdr->sh_name = 0x0;
  shdr->sh_type = SHT_PROGBITS;
  shdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  shdr->sh_addr = prev_shdr->sh_addr + prev_shdr->sh_size;
  shdr->sh_offset = prev_shdr->sh_offset + prev_shdr->sh_size;
  shdr->sh_size = sizeof(decode_stub);
  shdr->sh_link = 0x0;
  shdr->sh_addralign = 0x10;
  shdr->sh_entsize = 0x0;
```

comme information. Ce qu'il faut faire gaffe est les autres parties de section header.
On a ajouteé notre section decoder donc il faut faire un decalage.
les autres section header doit avoir un nouveau sh_offset qui est `shdr->sh_offset += sizeof(decode_stub);`

Ensuite on va integrer notre decoder dans la zone qu'on vient de creer.
On va copier en dure dans le binaire les instruction a executer pour decoder .text

Puis on va modifier le Program header en sorte que la partie decoder peut etre executer et que la partie .text peut etre ecrit. 

Example:

```
root@debian-ryaoi:~/woody-woodpacker# readelf -l ../woody
Elf file type is EXEC (Executable file)
Entry point 0x600918
There are 8 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001c0 0x00000000000001c0  R E    0x8
  INTERP         0x0000000000000200 0x0000000000400200 0x0000000000400200
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x00000000000006e4 0x00000000000006e4  RWE    0x200000
  LOAD           0x00000000000006e8 0x00000000006006e8 0x00000000006006e8
                 0x00000000000002a9 0x00000000000002a9  RWE    0x200000
  DYNAMIC        0x0000000000000700 0x0000000000600700 0x0000000000600700
                 0x00000000000001d0 0x00000000000001d0  RW     0x8
  NOTE           0x000000000000021c 0x000000000040021c 0x000000000040021c
                 0x0000000000000020 0x0000000000000020  R      0x4
  GNU_EH_FRAME   0x00000000000005a4 0x00000000004005a4 0x00000000004005a4
                 0x0000000000000034 0x0000000000000034  R      0x4
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss
   04     .dynamic
   05     .note.ABI-tag
   06     .eh_frame_hdr
   07
```

Il ne faut pas oublier de modifier le offset, FileSiz, VirtualAddr, MemSiz aussi car on a ajoute notre decoder dans le binaire.






