#include "assembler.h"

// https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/MOVK--Move-wide-with-keep-?lang=en
// movk encoding:
// 0 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
//------------------------------------------------------------------------
// sf|opc              |hw   |imm16                            |rd
uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
    return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
}

void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr) {
    arr[0] = cpu_to_le32(assemble_movk(addr & 0xffff, 0b0, rd));
    arr[1] = cpu_to_le32(assemble_movk((addr & 0xffff0000) >> 16, 0b1, rd));
    arr[2] = cpu_to_le32(assemble_movk((addr & 0xffff00000000) >> 32, 0b10, rd));
    arr[3] = cpu_to_le32(assemble_movk((addr & 0xffff000000000000) >> 48, 0b11, rd));
}
