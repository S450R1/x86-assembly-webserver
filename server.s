.intel_syntax noprefix
.global _start

/* DATA */
.section .data
sockaddr_in:
    .word 2                /* AF_INET */
    .word 0x5000           /* port 80 (0x0050 little-endian) */
    .long 0                /* INADDR_ANY */
    .zero 8

response_ok:
    .ascii "HTTP/1.0 200 OK\r\n\r\n"
.equ response_ok_len, . - response_ok

response_not_found:
    .ascii "HTTP/1.0 404 Not Found\r\n\r\n"
.equ response_404_len, . - response_not_found

content_label:
    .ascii "Content-Length:"
    .byte 0

/* BSS */
.section .bss
buffer:         .space 8192
filebuf:        .space 4096
content_length: .quad 0

/* TEXT */
.section .text
_start:
    /* socket(AF_INET, SOCK_STREAM, 0) */
    mov rdi, 2
    mov rsi, 1
    xor rdx, rdx
    mov rax, 41
    syscall
    mov rbx, rax            /* listening socket */

    /* bind(sockfd, &sockaddr_in, 16) */
    mov rdi, rbx
    lea rsi, [rip + sockaddr_in]
    mov rdx, 16
    mov rax, 49
    syscall

    /* listen(sockfd, 0) */
    mov rdi, rbx
    xor rsi, rsi
    mov rax, 50
    syscall

accept_loop:
    /* accept(sockfd, NULL, NULL) */
    mov rdi, rbx
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 43
    syscall
    mov r12, rax            /* client fd */

    /* fork() */
    mov rax, 57
    syscall
    test rax, rax
    jnz parent_close_client

    /* ===== child ===== */
    /* close(listen socket) */
    mov rdi, rbx
    mov rax, 3
    syscall

    /* read initial chunk into buffer (headers + maybe some body) */
    mov rdi, r12            /* client fd */
    lea rsi, [rip + buffer]
    mov rdx, 8192
    xor rax, rax
    syscall
    test rax, rax
    js child_exit_noop
    mov r15, rax            /* bytes_read */

    /* compute buffer_end = buffer + bytes_read in r14 */
    lea r14, [rip + buffer]
    add r14, r15

    /* Determine method: check first byte at buffer */
    mov al, byte ptr [rip + buffer]
    cmp al, 'G'             /* GET? */
    je handle_get
    cmp al, 'P'             /* POST? */
    je handle_post

    /* Unknown method -> just close and exit */
    jmp child_exit_noop

/* ------------------------- GET Handler ------------------------- */
handle_get:
    /* Path starts at buffer + 4 (skip "GET ") */
    lea r11, [rip + buffer]
    add r11, 4

    /* Sanitize path: terminate at space or newline */
    mov rdi, r11
sanitize_get_path:
    mov al, byte ptr [rdi]
    cmp al, 0x0A        /* newline */
    je get_path_done
    cmp al, 0x20        /* space */
    je get_path_done
    inc rdi
    jmp sanitize_get_path
get_path_done:
    mov byte ptr [rdi], 0

    /* open(path, O_RDONLY) */
    mov rdi, r11
    xor rsi, rsi        /* O_RDONLY = 0 */
    mov rax, 2          /* sys_open */
    syscall
    mov r13, rax
    cmp r13, 0
    js get_send_404     /* open failed */

    /* read(file_fd, filebuf, 4096) */
    mov rdi, r13
    lea rsi, [rip + filebuf]
    mov rdx, 4096
    xor rax, rax        /* sys_read */
    syscall
    mov r14, rax        /* bytes read */

    /* close(file_fd) */
    mov rdi, r13
    mov rax, 3
    syscall

    /* write(client_fd, response_ok, response_ok_len) */
    mov rdi, r12
    lea rsi, [rip + response_ok]
    mov rdx, response_ok_len
    mov rax, 1
    syscall

    /* write file contents */
    mov rdi, r12
    lea rsi, [rip + filebuf]
    mov rdx, r14
    mov rax, 1
    syscall

    /* close client and exit child */
    mov rdi, r12
    mov rax, 3
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall

get_send_404:
    /* send 404 and exit */
    mov rdi, r12
    lea rsi, [rip + response_not_found]
    mov rdx, response_404_len
    mov rax, 1
    syscall

    mov rdi, r12
    mov rax, 3
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall

/* ------------------------- POST Handler ------------------------- */
handle_post:
    /* Path starts at buffer + 5 (skip "POST ") */
    lea r11, [rip + buffer]
    add r11, 5

    /* Sanitize path: terminate at space or newline */
    mov rdi, r11
sanitize_post_path:
    mov al, byte ptr [rdi]
    cmp al, 0x0A
    je post_headers_start
    cmp al, 0x20
    je post_headers_start
    inc rdi
    jmp sanitize_post_path
post_headers_start:
    mov byte ptr [rdi], 0

    /* default content_length = 0 */
    xor rax, rax
    mov qword ptr [rip + content_length], rax

    /* scan headers region (buffer..buffer_end) for Content-Length */
    lea rsi, [rip + buffer]
find_content_scan:
    cmp rsi, r14
    jae cl_not_found
    mov al, byte ptr [rsi]
    cmp al, 'C'
    jne advance_cl_scan
    /* attempt match */
    lea rdx, [rip + content_label]
    push rsi
    push rdx
cmp_cl_loop:
    mov al, byte ptr [rsi]
    mov bl, byte ptr [rdx]
    cmp bl, 0
    je cl_label_ok
    cmp al, bl
    jne cl_label_fail
    inc rsi
    inc rdx
    jmp cmp_cl_loop

cl_label_fail:
    pop rdx
    pop rsi
    jmp advance_cl_scan

cl_label_ok:
    /* rsi now points right after the matched label (after the ':') */
skip_spaces_cl:
    mov al, byte ptr [rsi]
    cmp al, ' '
    jne parse_cl_number
    inc rsi
    jmp skip_spaces_cl

parse_cl_number:
    xor rax, rax
parse_cl_digits:
    mov bl, byte ptr [rsi]
    cmp bl, '0'
    jb done_cl_number
    cmp bl, '9'
    ja done_cl_number
    imul rax, rax, 10
    sub bl, '0'
    add rax, rbx
    inc rsi
    jmp parse_cl_digits

done_cl_number:
    mov qword ptr [rip + content_length], rax
    pop rdx
    pop rsi
    jmp after_cl_scan

advance_cl_scan:
    inc rsi
    jmp find_content_scan

cl_not_found:
    /* content_length remains 0 */

after_cl_scan:
    /* find end-of-headers to locate body start */
    lea rsi, [rip + buffer]
find_hdr_end:
    cmp rsi, r14
    jae hdr_notfound2
    mov edx, dword ptr [rsi]
    cmp edx, 0x0A0D0A0D      /* little-endian "\r\n\r\n" */
    je hdr_found_crlf
    mov al, byte ptr [rsi]
    cmp al, 0x0A
    jne hdr_inc
    mov bl, byte ptr [rsi + 1]
    cmp bl, 0x0A
    je hdr_found_nl
hdr_inc:
    add rsi, 1
    jmp find_hdr_end

hdr_notfound2:
    /* no header terminator -> assume no body present in this read */
    xor rax, rax
    mov qword ptr [rip + content_length], rax
    jmp hdr_done

hdr_found_crlf:
    add rsi, 4
    jmp hdr_done
hdr_found_nl:
    add rsi, 2
hdr_done:
    /* rsi is the body start pointer (or > buffer_end if not found) */

    /* compute available_body = bytes_in_buffer_after_headers */
    lea rax, [rip + buffer]
    mov rbx, r15                /* total bytes read */
    cmp rsi, rax
    jb avail_zero
    mov rcx, rsi
    sub rcx, rax                /* offset of body start */
    mov rax, r15
    sub rax, rcx                /* available body bytes */
    jmp avail_set
avail_zero:
    xor rax, rax
avail_set:
    mov r10, rax                /* r10 = available body bytes in buffer */

    /* if content_length == 0 => fallback to available (body only present) */
    mov rax, qword ptr [rip + content_length]
    cmp rax, 0
    jne cl_known
    mov rax, r10
    mov qword ptr [rip + content_length], rax

cl_known:
    /* open target file for writing: O_WRONLY|O_CREAT, mode 0777 (flags=65, mode=511) */
    mov rdi, r11                /* pathname */
    mov rsi, 65                 /* O_WRONLY|O_CREAT */
    mov rdx, 511                /* 0777 */
    mov rax, 2                  /* open */
    syscall
    mov r13, rax
    cmp r13, 0
    js post_cleanup_respond     /* open failed -> respond anyway */

    /* compute pointer to body start (re-run header terminator scan) */
    lea rsi, [rip + buffer]
find_body_ptr:
    cmp rsi, r14
    jae body_not_found
    mov edx, dword ptr [rsi]
    cmp edx, 0x0A0D0A0D
    je body_set_crlf
    mov al, byte ptr [rsi]
    cmp al, 0x0A
    jne body_inc
    mov bl, byte ptr [rsi + 1]
    cmp bl, 0x0A
    jne body_inc
    add rsi, 2
    jmp body_ptr_ready
body_set_crlf:
    add rsi, 4
    jmp body_ptr_ready
body_inc:
    add rsi, 1
    jmp find_body_ptr

body_not_found:
    /* nothing from initial buffer */
    xor rsi, rsi
    jmp body_ptr_ready

body_ptr_ready:
    /* rsi points to start of body in buffer (or 0) */
    /* compute total_to_write = content_length */
    mov rax, qword ptr [rip + content_length]
    mov rbx, rax                /* rbx = remaining bytes to write */

    /* calculate available bytes in buffer (again) */
    cmp rsi, 0
    je buf_empty
    lea rdx, [rip + buffer]
    mov rcx, r14
    sub rcx, rdx                /* rcx = total_read (r15) */
    /* offset = rsi - buffer */
    mov rdx, rsi
    sub rdx, qword ptr [rip + buffer]
    mov rax, r15
    sub rax, rdx                /* available in buffer */
    mov r10, rax
    jmp buf_avail_done
buf_empty:
    mov r10, 0
buf_avail_done:

    /* write available first (cap at remaining rbx) */
    cmp r10, 0
    je write_more_reads
    mov rax, rbx
    cmp r10, rax
    jle write_from_buffer
    mov r10, rax

write_from_buffer:
    mov rdi, r13                /* file fd */
    mov rdx, r10
    /* rsi is already body pointer */
    mov rax, 1                  /* write */
    syscall
    /* assume full write; subtract */
    mov rax, qword ptr [rip + content_length]
    sub rax, r10
    mov rbx, rax

    /* if all written, close and respond */
    cmp rbx, 0
    je post_close_respond

write_more_reads:
    /* loop: read from client and write until rbx == 0 */
read_write_loop:
    cmp rbx, 0
    je post_close_respond

    /* read into filebuf */
    mov rdi, r12
    lea rsi, [rip + filebuf]
    mov rdx, 4096
    xor rax, rax
    syscall
    test rax, rax
    jle post_close_respond      /* EOF or error -> finish up */

    /* rax = bytes read into filebuf; limit to rbx */
    mov rcx, rax
    mov rax, rcx
    cmp rax, rbx
    jle wr_ok
    mov rax, rbx
wr_ok:
    /* write rax bytes from filebuf to file */
    mov rdx, rax
    mov rdi, r13
    lea rsi, [rip + filebuf]
    mov rax, 1
    syscall
    /* subtract written from remaining */
    sub rbx, rdx
    jmp read_write_loop

post_close_respond:
    /* close file */
    mov rdi, r13
    mov rax, 3
    syscall

    /* send HTTP/1.0 200 OK */
    mov rdi, r12
    lea rsi, [rip + response_ok]
    mov rdx, response_ok_len
    mov rax, 1
    syscall

    /* close client and exit child */
    mov rdi, r12
    mov rax, 3
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall

post_cleanup_respond:
    /* open failed or other error path -> send 200 anyway (or 404) */
    mov rdi, r12
    lea rsi, [rip + response_ok]
    mov rdx, response_ok_len
    mov rax, 1
    syscall

    mov rdi, r12
    mov rax, 3
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall

child_exit_noop:
    /* close client and exit */
    mov rdi, r12
    mov rax, 3
    syscall
    xor rdi, rdi
    mov rax, 60
    syscall

parent_close_client:
    /* parent closes client fd and loops */
    mov rdi, r12
    mov rax, 3
    syscall
    jmp accept_loop
