ENTRY(__start)
SECTIONS {
  . = 0x80003100;
  .text : { *(.text .text.*) }
  . = ALIGN(32);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(32);
  .data : { *(.data .data.* .sdata .sdata.*) }
  . = ALIGN(32);
  .bss : { *(.sbss .sbss.* .bss .bss.* COMMON) }
}
