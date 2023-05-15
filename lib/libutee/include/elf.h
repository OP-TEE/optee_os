/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Huawei Technologies Co., Ltd
 */
#ifndef _ELF_H_
#define _ELF_H_

#if defined(ARM32) || defined(RV32)

#include <elf32.h>

typedef Elf32_Addr Elf_Addr;
typedef Elf32_Half Elf_Half;
typedef Elf32_Off Elf_Off;
typedef Elf32_Sword Elf_Sword;
typedef Elf32_Word Elf_Word;
typedef Elf32_Lword Elf_Lword;
typedef Elf32_Hashelt Elf_Hashelt;
typedef Elf32_Size Elf_Size;
typedef Elf32_Ssize Elf_Ssize;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
typedef Elf32_Phdr Elf_Phdr;
typedef Elf32_Dyn Elf_Dyn;
typedef Elf32_Rel Elf_Rel;
typedef Elf32_Rela Elf_Rela;
typedef Elf32_Move Elf_Move;
typedef Elf32_Cap Elf_Cap;
typedef Elf32_Sym Elf_Sym;
typedef Elf32_Verdef Elf_Verdef;
typedef Elf32_Verdaux Elf_Verdaux;
typedef Elf32_Verneed Elf_Verneed;
typedef Elf32_Vernaux Elf_Vernaux;
typedef Elf32_Syminfo Elf_Syminfo;

#elif defined(ARM64) || defined(RV64)

#include <elf64.h>

typedef Elf64_Addr Elf_Addr;
typedef Elf64_Half Elf_Half;
typedef Elf64_Off Elf_Off;
typedef Elf64_Sword Elf_Sword;
typedef Elf64_Sxword Elf_Sxword;
typedef Elf64_Word Elf_Word;
typedef Elf64_Lword Elf_Lword;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_Hashelt Elf_Hashelt;
typedef Elf64_Size Elf_Size;
typedef Elf64_Ssize Elf_Ssize;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Dyn Elf_Dyn;
typedef Elf64_Rel Elf_Rel;
typedef Elf64_Rela Elf_Rela;
typedef Elf64_Move Elf_Move;
typedef Elf64_Cap Elf_Cap;
typedef Elf64_Sym Elf_Sym;
typedef Elf64_Verdef Elf_Verdef;
typedef Elf64_Verdaux Elf_Verdaux;
typedef Elf64_Verneed Elf_Verneed;
typedef Elf64_Vernaux Elf_Vernaux;
typedef Elf64_Syminfo Elf_Syminfo;

#else
#error Unknown architecture
#endif

#endif /* _ELF_H_ */
