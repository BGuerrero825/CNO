ifndef X64
.386
.model flat, c
.safeseh CheckHypervisorPort
endif

.code

;;
; Checks if hypervisor port is being used
;
; @return 1 if hypervisor port is in use; 0 otherwise
CheckHypervisorPort PROC public
ifndef X64
    push   edx
    push   ecx
    push   ebx
else
    push   rdx
    push   rcx
    push   rbx
endif

    ;
    ; IN is an assembly language opcode that reads input from a port specified by
    ;   DX register. See the documentation for specific ports for more information
    ;   on their usage.
    ;
    ; Doing a IN on port 'VX' (i.e. 0x5658, the VMware hypervisor virtual port) with the registers setup
    ;   as described below, sets the value of the ebx register to 'VMXh' (i.e. 0x564D5868, the VMware
    ;   hypervisor magic value)
    ;
    ; Before calling IN, ensure that ebx DOES NOT contain the magic value (so you'll know if it was set),
    ;   eax DOES contain the magic value, ecx has the get version command id (i.e. 10), and edx contains
    ;   the virtual port number 'VX'
    ;
    ; 1) Set initial values for registers
    ; 2) Call IN on port 'VX'
    ; 3) Running under VMware hypervisor if ebx equals magic value ('VMXh')
    ;
    ; START: //////////////////////////// LAB2: VMware Virtual Port (Part 2) ////////////////////////////


    xor     ebx, ebx        ;
    mov     ecx, 0000000ah  ; GetVersionAction (10d), command to be run
    mov     eax, "VMXh"     ; VMXh, "magic number" at port
    mov     edx, "VX"       ; VX, move the VMware port number into edx

    in      eax, dx         ; use the in instruction

    mov     eax, "VMXh"     ; VMXh, "magic number" at port
    cmp     eax, ebx        ; compare returned port value to magic

    ; the following opcode sets al to true (1) or false (0) based on the zero/equal flag to make setting
    ;       the return value easy
    setz    al              ; set return value

    ; END:   //////////////////////////// LAB2: VMware Virtual Port (Part 2) ////////////////////////////

ifndef X64
    pop    ebx
    pop    ecx
    pop    edx
else
    pop    rbx
    pop    rcx
    pop    rdx
endif

    ret
CheckHypervisorPort ENDP

end
