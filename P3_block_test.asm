; mk: $mkAS && ld -o $mkBASE /usr/lib/x86_64-linux-gnu/crt1.o $mkBASE.o /usr/lib/x86_64-linux-gnu/crti.o /usr/lib/x86_64-linux-gnu/crtn.o -lc -I/lib64/ld-linux-x86-64.so.2

; Provide a test case for the blocks assignment.
; This program has a main program (that your code
; should find) and has a few basic blocks you should
; also discover, and one you might not.
;
; Also there are references outside the .text section
; so you can test for that.  Really, you should create
; this sort of test case for your code *before* you
; even write the code.

        global main
        
        extern puts

        section .text

        ; This code is unreachable and should not show up in your
        ; output.
start:
        push    rbp
        mov     rbp, rsp
        lea     rax, [rdi]
        pop     rbp
        ret
        db      0x48, 0x7f

        ; This is the main function, and it is where your processing
        ; should start.
main:
        push    rbp
        mov     rbp, rsp
        xor     eax, eax
        shl     rax, 1
        jae     .skip
        jz      .tail
        db      0x7f

        ; The code above this ends with an opaque predicate (the jae is
        ; always taken; be sure you understand why).  The data byte just
        ; messes things up.
.skip:
        lea     rax, [rel msg]
        mov     rdi, rax

        ; This calls the function in the other section.  It is a
        ; potential leader, but it is out of range and it should
        ; therefore not be in your result.
        call    print
        mov     ecx, 64
        mov     rsi, 0xf0a41022cafebabe
        lea     rdi, [rel buffer]

        ; Another basic block.  You reach this via the loop
        ; instruction or by falling through from the above
        ; block.
align 8
.top:
        call    .bitshift
        inc     rdi
        loop    .top

        ; Another basic block starts here.
        mov     [rdi], byte 0
        lea     rdi, [rel buffer]

        ; Again, print is out of range.
        call    print
        mov     rax, 0

        ; There is a (false) branch here near the top.
.tail:
        mov     rsp, rbp
        pop     rbp
        ret

        ; This is caught because there is an explicit call to it.
.bitshift:
        shl     rsi, 1
        mov     al, 0x18
        rcl     al, 1
        mov     [rdi], al
        ret

        ; Another section.  For fun, remove exec from the line
        ; below and see what happens.  Can you explain why that
        ; happens?
        section subroutines exec nowrite align=16

print:
        push    rbp
        mov     rbp, rsp
        and     rsp, -16
        call    puts wrt ..plt
        mov     rsp, rbp
        pop     rbp
        ret

        section .data align=16

msg:
        db      'Result is:', 0, 0

        section .bss align=16

buffer:
        resb    65

	section .note.GNU-stack

