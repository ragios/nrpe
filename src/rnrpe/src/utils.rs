#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(c_variadic, extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn rand() -> libc::c_int;
    fn srand(__seed: libc::c_uint);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn setenv(
        __name: *const libc::c_char,
        __value: *const libc::c_char,
        __replace: libc::c_int,
    ) -> libc::c_int;
    fn unsetenv(__name: *const libc::c_char) -> libc::c_int;
    fn bzero(_: *mut libc::c_void, _: libc::c_ulong);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    fn getuid() -> __uid_t;
    fn syslog(__pri: libc::c_int, __fmt: *const libc::c_char, _: ...);
    fn __fxstat(
        __ver: libc::c_int,
        __fildes: libc::c_int,
        __stat_buf: *mut stat,
    ) -> libc::c_int;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn socket(
        __domain: libc::c_int,
        __type: libc::c_int,
        __protocol: libc::c_int,
    ) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
    fn connect(
        __fd: libc::c_int,
        __addr: *const sockaddr,
        __len: socklen_t,
    ) -> libc::c_int;
    fn send(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn recv(
        __fd: libc::c_int,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
    ) -> ssize_t;
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn gai_strerror(__ecode: libc::c_int) -> *const libc::c_char;
    fn getnameinfo(
        __sa: *const sockaddr,
        __salen: socklen_t,
        __host: *mut libc::c_char,
        __hostlen: socklen_t,
        __serv: *mut libc::c_char,
        __servlen: socklen_t,
        __flags: libc::c_int,
    ) -> libc::c_int;
    fn getpwuid(__uid: __uid_t) -> *mut passwd;
    fn getpwnam(__name: *const libc::c_char) -> *mut passwd;
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    fn fgetc(__stream: *mut FILE) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fdopen(__fd: libc::c_int, __modes: *const libc::c_char) -> *mut FILE;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    static mut stderr: *mut FILE;
    static mut stdout: *mut FILE;
    static mut disable_syslog: libc::c_int;
    fn asprintf(
        ptr: *mut *mut libc::c_char,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn vasprintf(
        ptr: *mut *mut libc::c_char,
        format: *const libc::c_char,
        ap: ::core::ffi::VaList,
    ) -> libc::c_int;
    static mut environ: *mut *mut libc::c_char;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type va_list = __builtin_va_list;
pub type __u_short = libc::c_ushort;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
pub type u_short = __u_short;
pub type time_t = __time_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
#[inline]
unsafe extern "C" fn fstat(
    mut __fd: libc::c_int,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __fxstat(1 as libc::c_int, __fd, __statbuf);
}
static mut crc32_table: [libc::c_ulong; 256] = [0; 256];
#[no_mangle]
pub static mut log_file: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut log_fp: *mut FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub unsafe extern "C" fn generate_crc32_table() {
    let mut crc: libc::c_ulong = 0;
    let mut poly: libc::c_ulong = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    poly = 0xedb88320 as libc::c_long as libc::c_ulong;
    i = 0 as libc::c_int;
    while i < 256 as libc::c_int {
        crc = i as libc::c_ulong;
        j = 8 as libc::c_int;
        while j > 0 as libc::c_int {
            if crc & 1 as libc::c_int as libc::c_ulong != 0 {
                crc = crc >> 1 as libc::c_int ^ poly;
            } else {
                crc >>= 1 as libc::c_int;
            }
            j -= 1;
        }
        crc32_table[i as usize] = crc;
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn calculate_crc32(
    mut buffer: *mut libc::c_char,
    mut buffer_size: libc::c_int,
) -> libc::c_ulong {
    let mut crc: libc::c_ulong = 0xffffffff as libc::c_uint as libc::c_ulong;
    let mut this_char: libc::c_int = 0;
    let mut current_index: libc::c_int = 0;
    current_index = 0 as libc::c_int;
    while current_index < buffer_size {
        this_char = *buffer.offset(current_index as isize) as libc::c_int;
        crc = crc >> 8 as libc::c_int & 0xffffff as libc::c_int as libc::c_ulong
            ^ crc32_table[((crc ^ this_char as libc::c_ulong)
                & 0xff as libc::c_int as libc::c_ulong) as usize];
        current_index += 1;
    }
    return crc ^ 0xffffffff as libc::c_uint as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn randomize_buffer(
    mut buffer: *mut libc::c_char,
    mut buffer_size: libc::c_int,
) {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut x: libc::c_int = 0;
    let mut seed: libc::c_int = 0;
    fp = fopen(
        b"/dev/urandom\0" as *const u8 as *const libc::c_char,
        b"r\0" as *const u8 as *const libc::c_char,
    );
    if !fp.is_null() {
        seed = fgetc(fp);
        fclose(fp);
    } else {
        seed = time(0 as *mut time_t) as libc::c_int;
    }
    srand(seed as libc::c_uint);
    x = 0 as libc::c_int;
    while x < buffer_size {
        *buffer
            .offset(
                x as isize,
            ) = ('0' as i32
            + (72.0f64 * rand() as libc::c_double
                / (2147483647 as libc::c_int as libc::c_double + 1.0f64)) as libc::c_int)
            as libc::c_char;
        x += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn my_connect(
    mut host: *const libc::c_char,
    mut hostaddr: *mut sockaddr_storage,
    mut port: u_short,
    mut address_family: libc::c_int,
    mut bind_address: *const libc::c_char,
    mut redirect_stderr: libc::c_int,
) -> libc::c_int {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut gaierr: libc::c_int = 0;
    let mut sock: libc::c_int = -(1 as libc::c_int);
    let mut output: *mut FILE = stderr;
    if redirect_stderr != 0 {
        output = stdout;
    }
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        b"%u\0" as *const u8 as *const libc::c_char,
        port as libc::c_int,
    );
    gaierr = getaddrinfo(host, strport.as_mut_ptr(), &mut hints, &mut aitop);
    if gaierr != 0 as libc::c_int {
        fprintf(
            output,
            b"Could not resolve hostname %.100s: %s\n\0" as *const u8
                as *const libc::c_char,
            host,
            gai_strerror(gaierr),
        );
        exit(1 as libc::c_int);
    }
    ai = aitop;
    while !ai.is_null() {
        if !((*ai).ai_family != 2 as libc::c_int && (*ai).ai_family != 10 as libc::c_int)
        {
            if getnameinfo(
                (*ai).ai_addr,
                (*ai).ai_addrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong
                    as socklen_t,
                strport.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong
                    as socklen_t,
                1 as libc::c_int | 2 as libc::c_int,
            ) != 0 as libc::c_int
            {
                fprintf(
                    output,
                    b"my_connect: getnameinfo failed\n\0" as *const u8
                        as *const libc::c_char,
                );
            } else {
                sock = my_create_socket(ai, bind_address, redirect_stderr);
                if !(sock < 0 as libc::c_int) {
                    if connect(sock, (*ai).ai_addr, (*ai).ai_addrlen) >= 0 as libc::c_int
                    {
                        memcpy(
                            hostaddr as *mut libc::c_void,
                            (*ai).ai_addr as *const libc::c_void,
                            (*ai).ai_addrlen as libc::c_ulong,
                        );
                        break;
                    } else {
                        fprintf(
                            output,
                            b"connect to address %s port %s: %s\n\0" as *const u8
                                as *const libc::c_char,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                            strerror(*__errno_location()),
                        );
                        close(sock);
                        sock = -(1 as libc::c_int);
                    }
                }
            }
        }
        ai = (*ai).ai_next;
    }
    freeaddrinfo(aitop);
    if sock == -(1 as libc::c_int) {
        fprintf(
            output,
            b"connect to host %s port %s: %s\n\0" as *const u8 as *const libc::c_char,
            host,
            strport.as_mut_ptr(),
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return sock;
}
unsafe extern "C" fn my_create_socket(
    mut ai: *mut addrinfo,
    mut bind_address: *const libc::c_char,
    mut redirect_stderr: libc::c_int,
) -> libc::c_int {
    let mut sock: libc::c_int = 0;
    let mut gaierr: libc::c_int = 0;
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    let mut output: *mut FILE = stderr;
    if redirect_stderr != 0 {
        output = stdout;
    }
    sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
    if sock < 0 as libc::c_int {
        fprintf(
            output,
            b"socket: %.100s\n\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    if bind_address.is_null() {
        return sock;
    }
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = (*ai).ai_family;
    hints.ai_socktype = (*ai).ai_socktype;
    hints.ai_protocol = (*ai).ai_protocol;
    hints.ai_flags = 0x1 as libc::c_int;
    gaierr = getaddrinfo(bind_address, 0 as *const libc::c_char, &mut hints, &mut res);
    if gaierr != 0 {
        fprintf(
            output,
            b"getaddrinfo: %s: %s\n\0" as *const u8 as *const libc::c_char,
            bind_address,
            gai_strerror(gaierr),
        );
        close(sock);
        return -(1 as libc::c_int);
    }
    if bind(sock, (*res).ai_addr, (*res).ai_addrlen) < 0 as libc::c_int {
        fprintf(
            output,
            b"bind: %s: %s\n\0" as *const u8 as *const libc::c_char,
            bind_address,
            strerror(*__errno_location()),
        );
        close(sock);
        freeaddrinfo(res);
        return -(1 as libc::c_int);
    }
    freeaddrinfo(res);
    return sock;
}
#[no_mangle]
pub unsafe extern "C" fn add_listen_addr(
    mut listen_addrs: *mut *mut addrinfo,
    mut address_family: libc::c_int,
    mut addr: *mut libc::c_char,
    mut port: libc::c_int,
) {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut gaierr: libc::c_int = 0;
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    hints.ai_flags = if addr.is_null() { 0x1 as libc::c_int } else { 0 as libc::c_int };
    snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        b"%d\0" as *const u8 as *const libc::c_char,
        port,
    );
    gaierr = getaddrinfo(addr, strport.as_mut_ptr(), &mut hints, &mut aitop);
    if gaierr != 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"bad addr or host: %s (%s)\n\0" as *const u8 as *const libc::c_char,
            if !addr.is_null() {
                addr as *const libc::c_char
            } else {
                b"<NULL>\0" as *const u8 as *const libc::c_char
            },
            gai_strerror(gaierr),
        );
        exit(1 as libc::c_int);
    }
    ai = aitop;
    while !((*ai).ai_next).is_null() {
        ai = (*ai).ai_next;
    }
    (*ai).ai_next = *listen_addrs;
    *listen_addrs = aitop;
}
#[no_mangle]
pub unsafe extern "C" fn clean_environ(
    mut keep_env_vars: *const libc::c_char,
    mut nrpe_user: *const libc::c_char,
) -> libc::c_int {
    static mut path: *mut libc::c_char = b"/usr/bin:/bin:/usr/sbin:/sbin\0" as *const u8
        as *const libc::c_char as *mut libc::c_char;
    let mut pw: *mut passwd = 0 as *mut passwd;
    let mut len: size_t = 0;
    let mut var_sz: size_t = 0 as libc::c_int as size_t;
    let mut kept: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut var: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keep: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut keepcnt: libc::c_int = 0 as libc::c_int;
    if !keep_env_vars.is_null() && *keep_env_vars as libc::c_int != 0 {
        asprintf(
            &mut keep as *mut *mut libc::c_char,
            b"%s,NRPE_MULTILINESUPPORT,NRPE_PROGRAMVERSION\0" as *const u8
                as *const libc::c_char,
            keep_env_vars,
        );
    } else {
        asprintf(
            &mut keep as *mut *mut libc::c_char,
            b"NRPE_MULTILINESUPPORT,NRPE_PROGRAMVERSION\0" as *const u8
                as *const libc::c_char,
        );
    }
    if keep.is_null() {
        logit(
            3 as libc::c_int,
            b"Could not sanitize the environment. Aborting!\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    keepcnt += 1;
    i = strlen(keep) as libc::c_int;
    loop {
        let fresh0 = i;
        i = i - 1;
        if !(fresh0 != 0) {
            break;
        }
        if *keep.offset(i as isize) as libc::c_int == ',' as i32 {
            keepcnt += 1;
        }
    }
    kept = calloc(
        (keepcnt + 1 as libc::c_int) as libc::c_ulong,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if kept.is_null() {
        logit(
            3 as libc::c_int,
            b"Could not sanitize the environment. Aborting!\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    var = my_strsep(&mut keep, b",\0" as *const u8 as *const libc::c_char);
    while !var.is_null() {
        let fresh1 = i;
        i = i + 1;
        let ref mut fresh2 = *kept.offset(fresh1 as isize);
        *fresh2 = strip(var);
        var = my_strsep(&mut keep, b",\0" as *const u8 as *const libc::c_char);
    }
    var = 0 as *mut libc::c_char;
    i = 0 as libc::c_int;
    while !(*environ.offset(i as isize)).is_null() {
        value = *environ.offset(i as isize);
        len = strcspn(value, b"=\0" as *const u8 as *const libc::c_char);
        if len == 0 as libc::c_int as libc::c_ulong {
            free(keep as *mut libc::c_void);
            free(kept as *mut libc::c_void);
            free(var as *mut libc::c_void);
            logit(
                3 as libc::c_int,
                b"Could not sanitize the environment. Aborting!\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if len >= var_sz {
            var_sz = len.wrapping_add(1 as libc::c_int as libc::c_ulong);
            var = realloc(var as *mut libc::c_void, var_sz) as *mut libc::c_char;
        }
        strncpy(var, *environ.offset(i as isize), var_sz);
        *var.offset(len as isize) = 0 as libc::c_int as libc::c_char;
        j = 0 as libc::c_int;
        while !(*kept.offset(j as isize)).is_null() {
            if strncmp(var, *kept.offset(j as isize), strlen(*kept.offset(j as isize)))
                == 0
            {
                break;
            }
            j += 1;
        }
        if !(*kept.offset(j as isize)).is_null() {
            i += 1;
        } else {
            unsetenv(var);
        }
    }
    free(var as *mut libc::c_void);
    free(keep as *mut libc::c_void);
    free(kept as *mut libc::c_void);
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    if !nrpe_user.is_null() {
        user = strdup(nrpe_user);
        pw = getpwnam(nrpe_user);
    }
    if nrpe_user.is_null() || pw.is_null() {
        pw = getpwuid(getuid());
        if !pw.is_null() {
            user = strdup((*pw).pw_name);
        }
    }
    if pw.is_null() {
        free(user as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    setenv(b"PATH\0" as *const u8 as *const libc::c_char, path, 1 as libc::c_int);
    setenv(
        b"IFS\0" as *const u8 as *const libc::c_char,
        b" \t\n\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    setenv(b"LOGNAME\0" as *const u8 as *const libc::c_char, user, 0 as libc::c_int);
    setenv(b"USER\0" as *const u8 as *const libc::c_char, user, 0 as libc::c_int);
    setenv(
        b"HOME\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
        0 as libc::c_int,
    );
    setenv(
        b"SHELL\0" as *const u8 as *const libc::c_char,
        (*pw).pw_shell,
        0 as libc::c_int,
    );
    free(user as *mut libc::c_void);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn strip(mut buffer: *mut libc::c_char) -> *mut libc::c_char {
    let mut x: libc::c_int = 0;
    let mut index: libc::c_int = 0;
    let mut buf: *mut libc::c_char = buffer;
    x = strlen(buffer) as libc::c_int;
    while x >= 1 as libc::c_int {
        index = x - 1 as libc::c_int;
        if !(*buffer.offset(index as isize) as libc::c_int == ' ' as i32
            || *buffer.offset(index as isize) as libc::c_int == '\r' as i32
            || *buffer.offset(index as isize) as libc::c_int == '\n' as i32
            || *buffer.offset(index as isize) as libc::c_int == '\t' as i32)
        {
            break;
        }
        *buffer.offset(index as isize) = '\0' as i32 as libc::c_char;
        x -= 1;
    }
    while *buf as libc::c_int == ' ' as i32 || *buf as libc::c_int == '\r' as i32
        || *buf as libc::c_int == '\n' as i32 || *buf as libc::c_int == '\t' as i32
    {
        buf = buf.offset(1);
        x -= 1;
    }
    if buf != buffer {
        memmove(
            buffer as *mut libc::c_void,
            buf as *const libc::c_void,
            x as libc::c_ulong,
        );
        *buffer.offset(x as isize) = '\0' as i32 as libc::c_char;
    }
    return buffer;
}
#[no_mangle]
pub unsafe extern "C" fn sendall(
    mut s: libc::c_int,
    mut buf: *mut libc::c_char,
    mut len: *mut libc::c_int,
) -> libc::c_int {
    let mut total: libc::c_int = 0 as libc::c_int;
    let mut bytesleft: libc::c_int = *len;
    let mut n: libc::c_int = 0 as libc::c_int;
    while total < *len {
        n = send(
            s,
            buf.offset(total as isize) as *const libc::c_void,
            bytesleft as size_t,
            0 as libc::c_int,
        ) as libc::c_int;
        if n == -(1 as libc::c_int) {
            break;
        }
        total += n;
        bytesleft -= n;
    }
    *len = total;
    return if n == -(1 as libc::c_int) { -(1 as libc::c_int) } else { 0 as libc::c_int };
}
#[no_mangle]
pub unsafe extern "C" fn recvall(
    mut s: libc::c_int,
    mut buf: *mut libc::c_char,
    mut len: *mut libc::c_int,
    mut timeout: libc::c_int,
) -> libc::c_int {
    let mut start_time: time_t = 0;
    let mut current_time: time_t = 0;
    let mut total: libc::c_int = 0 as libc::c_int;
    let mut bytesleft: libc::c_int = *len;
    let mut n: libc::c_int = 0 as libc::c_int;
    bzero(buf as *mut libc::c_void, *len as libc::c_ulong);
    time(&mut start_time);
    while total < *len {
        n = recv(
            s,
            buf.offset(total as isize) as *mut libc::c_void,
            bytesleft as size_t,
            0 as libc::c_int,
        ) as libc::c_int;
        if n == -(1 as libc::c_int) && *__errno_location() == 11 as libc::c_int {
            time(&mut current_time);
            if current_time - start_time > timeout as libc::c_long {
                break;
            }
            sleep(1 as libc::c_int as libc::c_uint);
        } else {
            if n <= 0 as libc::c_int {
                break;
            }
            total += n;
            bytesleft -= n;
        }
    }
    *len = total;
    return if n <= 0 as libc::c_int { n } else { total };
}
#[no_mangle]
pub unsafe extern "C" fn my_strsep(
    mut stringp: *mut *mut libc::c_char,
    mut delim: *const libc::c_char,
) -> *mut libc::c_char {
    let mut begin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    begin = *stringp;
    if begin.is_null() {
        return 0 as *mut libc::c_char;
    }
    if *delim.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32
        || *delim.offset(1 as libc::c_int as isize) as libc::c_int == '\0' as i32
    {
        let mut ch: libc::c_char = *delim.offset(0 as libc::c_int as isize);
        if ch as libc::c_int == '\0' as i32 {
            end = 0 as *mut libc::c_char;
        } else if *begin as libc::c_int == ch as libc::c_int {
            end = begin;
        } else {
            end = strchr(begin.offset(1 as libc::c_int as isize), ch as libc::c_int);
        }
    } else {
        end = strpbrk(begin, delim);
    }
    if !end.is_null() {
        let fresh3 = end;
        end = end.offset(1);
        *fresh3 = '\0' as i32 as libc::c_char;
        *stringp = end;
    } else {
        *stringp = 0 as *mut libc::c_char;
    }
    return begin;
}
#[no_mangle]
pub unsafe extern "C" fn open_log_file() {
    let mut fh: libc::c_int = 0;
    let mut flags: libc::c_int = 0o2 as libc::c_int | 0o2000 as libc::c_int
        | 0o100 as libc::c_int;
    let mut st: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    close_log_file();
    if log_file.is_null() {
        return;
    }
    flags |= 0o400000 as libc::c_int;
    fh = open(
        log_file,
        flags,
        0o400 as libc::c_int | 0o200 as libc::c_int
            | 0o400 as libc::c_int >> 3 as libc::c_int
            | 0o400 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int,
    );
    if fh == -(1 as libc::c_int) {
        printf(
            b"Warning: Cannot open log file '%s' for writing\n\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        logit(
            4 as libc::c_int,
            b"Warning: Cannot open log file '%s' for writing\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        return;
    }
    log_fp = fdopen(fh, b"a+\0" as *const u8 as *const libc::c_char);
    if log_fp.is_null() {
        printf(
            b"Warning: Cannot open log file '%s' for writing\n\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        logit(
            4 as libc::c_int,
            b"Warning: Cannot open log file '%s' for writing\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        return;
    }
    if fstat(fh, &mut st) == -(1 as libc::c_int) {
        log_fp = 0 as *mut FILE;
        close(fh);
        printf(
            b"Warning: Cannot fstat log file '%s'\n\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        logit(
            4 as libc::c_int,
            b"Warning: Cannot fstat log file '%s'\0" as *const u8 as *const libc::c_char,
            log_file,
        );
        return;
    }
    if st.st_nlink != 1 as libc::c_int as libc::c_ulong
        || st.st_mode & 0o170000 as libc::c_int as libc::c_uint
            != 0o100000 as libc::c_int as libc::c_uint
    {
        log_fp = 0 as *mut FILE;
        close(fh);
        printf(
            b"Warning: log file '%s' has an invalid mode\n\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        logit(
            4 as libc::c_int,
            b"Warning: log file '%s' has an invalid mode\0" as *const u8
                as *const libc::c_char,
            log_file,
        );
        return;
    }
    fcntl(fileno(log_fp), 2 as libc::c_int, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn logit(
    mut priority: libc::c_int,
    mut format: *const libc::c_char,
    mut args: ...
) {
    let mut log_time: time_t = 0 as libc::c_long;
    let mut ap: ::core::ffi::VaListImpl;
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    if format.is_null() || *format == 0 {
        return;
    }
    ap = args.clone();
    if vasprintf(&mut buffer, format, ap.as_va_list()) > 0 as libc::c_int {
        if !log_fp.is_null() {
            time(&mut log_time);
            strip(buffer);
            fprintf(
                log_fp,
                b"[%llu] %s\n\0" as *const u8 as *const libc::c_char,
                log_time as libc::c_ulonglong,
                buffer,
            );
            fflush(log_fp);
        } else if disable_syslog == 0 {
            syslog(priority, b"%s\0" as *const u8 as *const libc::c_char, buffer);
        }
        free(buffer as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn close_log_file() {
    if log_fp.is_null() {
        return;
    }
    fflush(log_fp);
    fclose(log_fp);
    log_fp = 0 as *mut FILE;
}
#[no_mangle]
pub unsafe extern "C" fn display_license() {
    printf(
        b"This program is released under the GPL (see below) with the additional\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"exemption that compiling, linking, and/or using OpenSSL is allowed.\n\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"This program is free software; you can redistribute it and/or modify\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"it under the terms of the GNU General Public License as published by\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"the Free Software Foundation; either version 2 of the License, or\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"(at your option) any later version.\n\n\0" as *const u8 as *const libc::c_char,
    );
    printf(
        b"This program is distributed in the hope that it will be useful,\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"but WITHOUT ANY WARRANTY; without even the implied warranty of\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"GNU General Public License for more details.\n\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"You should have received a copy of the GNU General Public License\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(
        b"along with this program; if not, write to the Free Software\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.\n\n\0" as *const u8
            as *const libc::c_char,
    );
}
