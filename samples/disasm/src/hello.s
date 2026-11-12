# DOS COM fixture for RevLens (written for this repo, CC0). Assembled with llvm-mc for 16 bit
# real mode; loads at 0x100.
  .code16
  .text
start:
  movb $0x09, %ah
  movw $msg+0x100, %dx
  int $0x21
  call addone
  cmpw $0x2a, %ax
  jne done
  movw $0x4c01, %ax
  int $0x21
done:
  movw $0x4c00, %ax
  int $0x21
addone:
  movw $0x29, %ax
  incw %ax
  ret
msg:
  .ascii "Hello from RevLens$"
