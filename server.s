.intel_syntax noprefix

.global _start

.section .text

_start:
        # socket(AF_INET, SOCK_STREAM, 0)
        mov rdi, 2 # AF_INET
        mov rsi, 1 # SOCK_STREAM
        mov rdx, 0 # protocol
        mov rax, 41 # syscall: socket
        syscall
        mov rbx, rax # save sockfd in rbx

        # bind(sockfd, sockaddr_in, 16)
        mov rdi, rbx
        lea rsi, [sockaddr_in]
        mov rdx, 16
        mov rax, 49 # syscall: bind
        syscall

        # listen(sockfd, 0)
        mov rdi, rbx
        mov rsi, 0
        mov rax, 50 # syscall: listen
        syscall

        request:
                # accept(sockfd, NULL, NULL)
                mov rdi, rbx
                mov rsi, 0
                mov rdx, 0
                mov rax, 43 # syscall: accept
                syscall
                mov r12, rax # client fd in r12

                # fork()
                mov rax, 57
                syscall
                test rax, rax
                jnz parent_process # if rax != 0 => parent

                # child process
                # close(sockfd)
                mov rdi, rbx
                mov rax, 3 # syscall: close
                syscall

                # read(client_fd, buffer, 1024)
                mov rdi, r12 # client fd
                lea rsi, [buffer] # buffer
                mov rdx, 1024 # max size
                mov rax, 0 # syscall: read
                syscall

                # skip "GET" (first 4 bytes) to extract path
                lea rsi, [buffer+4] # pathname starts after "GET"
                mov rdi, rsi # to loop the pathname for sanitization

                sanitize_path:
                        mov al, byte ptr [rdi]
                        cmp al, 0x0A # newline?
                        je set_zero
                        cmp al, 0x20 # space ?
                        je set_zero
                        inc rdi
                        jmp sanitize_path

                set_zero:
                        mov byte ptr [rdi], 0 # terminate string

                # open(pathname, O_RDONLY)
                mov rdi, rsi
                mov rsi, 0 # O_RDONLY
                mov rax, 2 # syscall: open
                syscall
                mov r13, rax # file fd

                # read(file_fd, filebuf, 4096)
                mov rdi, r13
                lea rsi, [filebuf]
                mov rdx, 4096
                mov rax, 0 # syscall: read
                syscall
                mov r14, rax # bytes read

                # close(file_fd)
                mov rdi, r13 # file fd
                mov rax, 3 # syscall: close
                syscall

                # write(client_fd, response_header, 19)
                mov rdi, r12
                lea rsi, [response]
                mov rdx, 19
                mov rax, 1 # syscall: write
                syscall

                # write(client_fd, message, length)
                mov rdi, r12 # client fd
                lea rsi, [filebuf] # pointer to response
                mov rdx, r14 # response length
                mov rax, 1 # syscall: close
                syscall
                jmp exit

                parent_process:
                        # close(client_fd)
                        mov rdi, r12 # client fd
                        mov rax, 3 # syscall: close
                        syscall
                        jmp request
        exit:
                # exit(0)
                mov rdi, 0
                mov rax, 60 # syscall: exit
                syscall

.section .data
        sockaddr_in:
                .word 2 # AF_INET
                .word 0x5000 # Port 80 in hex little-endian => 0x0050
                .long 0 # INADDR_ANY 0.0.0.0
                .zero 8 # 0 padding

        response: .ascii "HTTP/1.0 200 OK\r\n\r\n"

        buffer: .space 1024 # input buffer
        filebuf: .space 4096 # file buffer