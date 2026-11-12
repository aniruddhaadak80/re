; Minimal NES program for header fixtures. Built twice with different headers (see build.sh).
.segment "HEADER"
.ifdef NES2
  ; NES 2.0: mapper 268 submapper 1, 128 KiB PRG, CHR RAM 8 KiB, PRG NVRAM 8 KiB, PAL, trainer, four-screen
  .byte "NES", $1A
  .byte 8, 0              ; PRG 8 x 16 KiB, CHR ROM none
  .byte $C6 | $08         ; mapper low nibble C, four-screen, trainer, battery
  .byte $08 | $00         ; NES 2.0 identifier, mapper bits 4-7 = 0
  .byte $11               ; submapper 1, mapper bits 8-11 = 1  -> mapper 0x10C = 268
  .byte $00               ; size MSBs
  .byte $70               ; PRG RAM none, PRG NVRAM 64 << 7 = 8 KiB
  .byte $07               ; CHR RAM 64 << 7 = 8 KiB
  .byte $01               ; PAL
  .byte $00, $00, $01     ; vs, misc ROMs, default expansion 1
.else
  ; iNES 1.0: mapper 1 (MMC1), 32 KiB PRG, 8 KiB CHR, vertical mirroring, battery
  .byte "NES", $1A
  .byte 2, 1
  .byte $13               ; mapper low nibble 1, battery, vertical
  .byte $00
  .byte 0, 0, 0, 0, 0, 0, 0, 0
.endif
.ifdef NES2
.segment "TRAINER"
  .byte "RevLens trainer"
  .res 512 - 15, 0
.endif
.segment "CODE"
reset:
  sei
  cld
  ldx #$ff
  txs
loop:
  jmp loop & $FFFF
nmi:
irq:
  rti
  .byte "RevLens NES fixture"
.segment "VECTORS"
  .word nmi & $FFFF, reset & $FFFF, irq & $FFFF
.ifndef NES2
.segment "CHARS"
  .byte $3c, $42, $81, $81, $81, $81, $42, $3c
.endif
