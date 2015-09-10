.CODE

start:

MY_FUNC PROC
        push rax ;Padding for calling alligned on 16 bytes + ret value
        push rax
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        mov rax, 0h
        push rax
        mov rax, 7845646165726854h
        push rax
        mov rax,  657461657243744eh
        push rax
        mov r11, rsp ;R11 NtCreateThreadEx
        mov rbx, 41797261h
        push rbx
        mov rbx,  7262694c64616f4ch
        push rbx
        mov r12, rsp ;R12 : LoadLib
        ;String pushed !
        ;mov rax, 0x60
        ;GS mov rax, [rax] ;PEB!
        mov rax, GS:[60h]
        mov rax, [rax + 6 * 4] ; RAX = ldr (+ 6 for 64 cause of 2 ptr)
        mov rax, [rax + 8 * 4] ; RAX on the first elt of the list (first module)
        mov rdx, rax
a_dest:
        mov rax, rdx
        mov rbx, [rax + 4 * 8] ;RBX : first base ! (base of current module)
        and rbx, rbx ;If no more Module : not fail = fail
        jz a_fail
        mov rcx, [rax + 10 * 8] ;RCX = NAME (UNICODE_STRING.Buffer)

        mov rcx, [rcx] ;GET WCHAR
        cmp ecx, 74006eh         ;ntdll if : ecx == 74006eh (nt unicode)
        jz dll_found
        mov rdx, [rax]
        jmp a_dest
a_fail:
        push 42424242h
        ret
dll_found: ;Cool ! : here rbx = base
        mov eax, [rbx + 15 * 4] ;rax = PEBASE RVA
        add rax, rbx ;RAX = PEBASE
        add rax, 24 ;OPTIONAL HEADER
        mov ecx, [rax + 112] ;rcx = RVA export dir
        add rcx, rbx ;rcx = export_dir
        mov rax, rcx ;RAX = export_dir
        push rax ;Save it for after function search
        ; EBX = BASE | EAX = EXPORT DIR
        mov ecx, [rax  + 6 * 4] 
        mov r13, rcx ;r13 = NB names
        mov edx, [rax + 8 * 4] ; EDX = names array RVA
        add rdx, rbx
        xor rcx, rcx
 search_loop:
        mov esi, [rdx + rcx * 4] ;Get function name RVA
        add rsi, rbx ;Get name addr
        push rcx ;Save current index (could use x64 register)
        mov rdi, r11
        mov rcx, 17 ;We know we want NtCreateThreadEx
        repe cmpsb ;cmp with current export
        mov eax, ecx
        pop rcx ;Restore current function index
        inc rcx
        test eax, eax
        jnz search_loop ;If not found not handled : WTF GetProcAddress not in Kernel32...
        ; Func found !
        dec rcx
        ; rcx is offset of the name, need to find the offset of the function
        pop rax ;Restore export_dir addr
        mov edx, [rax + 9 * 4] ;EDX = AddressOfNameOrdinals RVX
        add rdx, rbx ;AddressOfNameOrdinals + base
        mov cx, [rdx + rcx * 2] ; ecx = Ieme ordinal (short array)
        and rcx, 0ffffh
        mov edx, [rax + 7 * 4] ; AddressOfFunctions RVA
        add rdx, rbx ; AddressOfFunctions + base
        mov edx, [rdx + rcx * 4] ;functions[ecx] -> functions[ordinals[i]]
        add rdx, rbx 
        mov r13, rdx ; r13 : REAL FUNC ADD
        
        
        ; room for the thread handle
        push 0
        mov rcx, rsp ; arg1
        mov rdx, 1fffffh ; arg2
        mov r8,  0h ; arg3
        mov r9, 4040404040404040h ; arg4 (handle)
        
        mov rax, 0h
        push rax ; arg11
        push rax ; arg10
        push rax ; arg9
        push rax ; arg8
        push rax ; arg7
        mov rax, 4242424242424242h 
        push rax ; arg6 (param)
        mov rax, 4141414141414141h
        push rax ; arg5 (addr)
        
        ; reserve space for register (calling convention)
        push r9
        push r8
        push rdx
        push rcx
        call r13
        ; Write return value in first stack value pushed
        mov [rsp + 29 * 8], rax
        ; TODO CLEAN stack :D
        add rsp, 8 * 8
        add rsp, 32 + 8
        add rsp, 32
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        pop rax ; Return value
        
MY_FUNC ENDP
END