#ifndef _ASSEMBLER_H_
#define _ASSEMBLER_H_

#include <linux/types.h>
#include <linux/delay.h>

#define INS_SIZE 4

extern uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd);
extern void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr);

#endif
