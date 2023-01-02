#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
//#![feature(asm, c_variadic, extern_types)]
#![feature(c_variadic, extern_types)]
use c2rust_asm_casts::AsmCastTrait;
use core::arch::asm;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type x509_st;
    pub type X509_name_st;
    pub type x509_store_ctx_st;
    pub type ossl_init_settings_st;
    pub type engine_st;
    pub type ssl_st;
    pub type ssl_ctx_st;
    pub type ssl_method_st;
    pub type ssl_cipher_st;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fdopen(__fd: libc::c_int, __modes: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn fgetc(__stream: *mut FILE) -> libc::c_int;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn fileno(__stream: *mut FILE) -> libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn strtoul(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_ulong;
    fn select(
        __nfds: libc::c_int,
        __readfds: *mut fd_set,
        __writefds: *mut fd_set,
        __exceptfds: *mut fd_set,
        __timeout: *mut timeval,
    ) -> libc::c_int;
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
    static mut optarg: *mut libc::c_char;
    static mut optind: libc::c_int;
    fn getopt_long(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
        __longopts: *const option,
        __longind: *mut libc::c_int,
    ) -> libc::c_int;
    fn bzero(_: *mut libc::c_void, _: libc::c_ulong);
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
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
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strncat(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strpbrk(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn alarm(__seconds: libc::c_uint) -> libc::c_uint;
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    fn getuid() -> __uid_t;
    fn sigfillset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;
    fn syslog(__pri: libc::c_int, __fmt: *const libc::c_char, _: ...);
    fn __xstat(
        __ver: libc::c_int,
        __filename: *const libc::c_char,
        __stat_buf: *mut stat,
    ) -> libc::c_int;
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
    fn getpeername(
        __fd: libc::c_int,
        __addr: *mut sockaddr,
        __len: *mut socklen_t,
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
    fn shutdown(__fd: libc::c_int, __how: libc::c_int) -> libc::c_int;
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
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
    fn ENGINE_register_all_complete() -> libc::c_int;
    fn ENGINE_load_builtin_engines();
    fn X509_verify_cert_error_string(n: libc::c_long) -> *const libc::c_char;
    fn X509_NAME_oneline(
        a: *const X509_NAME,
        buf: *mut libc::c_char,
        size: libc::c_int,
    ) -> *mut libc::c_char;
    fn X509_get_issuer_name(a: *const X509) -> *mut X509_NAME;
    fn X509_get_subject_name(a: *const X509) -> *mut X509_NAME;
    fn SSL_CTX_set_options(ctx_0: *mut SSL_CTX, op: libc::c_ulong) -> libc::c_ulong;
    fn SSL_CTX_set_cipher_list(_: *mut SSL_CTX, str: *const libc::c_char) -> libc::c_int;
    fn SSL_CTX_new(meth_0: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(_: *mut SSL_CTX);
    fn SSL_get_current_cipher(s: *const SSL) -> *const SSL_CIPHER;
    fn SSL_CIPHER_get_version(c: *const SSL_CIPHER) -> *const libc::c_char;
    fn SSL_CIPHER_get_name(c: *const SSL_CIPHER) -> *const libc::c_char;
    fn SSL_set_fd(s: *mut SSL, fd: libc::c_int) -> libc::c_int;
    fn SSL_CTX_use_PrivateKey_file(
        ctx_0: *mut SSL_CTX,
        file: *const libc::c_char,
        type_0: libc::c_int,
    ) -> libc::c_int;
    fn SSL_CTX_use_certificate_chain_file(
        ctx_0: *mut SSL_CTX,
        file: *const libc::c_char,
    ) -> libc::c_int;
    fn SSL_get_peer_certificate(s: *const SSL) -> *mut X509;
    fn SSL_CTX_set_verify(
        ctx_0: *mut SSL_CTX,
        mode: libc::c_int,
        callback: SSL_verify_cb,
    );
    fn SSL_new(ctx_0: *mut SSL_CTX) -> *mut SSL;
    fn SSL_free(ssl_0: *mut SSL);
    fn SSL_connect(ssl_0: *mut SSL) -> libc::c_int;
    fn SSL_read(
        ssl_0: *mut SSL,
        buf: *mut libc::c_void,
        num: libc::c_int,
    ) -> libc::c_int;
    fn SSL_write(
        ssl_0: *mut SSL,
        buf: *const libc::c_void,
        num: libc::c_int,
    ) -> libc::c_int;
    fn SSL_CTX_ctrl(
        ctx_0: *mut SSL_CTX,
        cmd: libc::c_int,
        larg: libc::c_long,
        parg: *mut libc::c_void,
    ) -> libc::c_long;
    fn SSL_get_error(s: *const SSL, ret_code: libc::c_int) -> libc::c_int;
    fn SSL_get_version(s: *const SSL) -> *const libc::c_char;
    fn TLS_method() -> *const SSL_METHOD;
    fn SSL_shutdown(s: *mut SSL) -> libc::c_int;
    fn SSL_CTX_load_verify_locations(
        ctx_0: *mut SSL_CTX,
        CAfile: *const libc::c_char,
        CApath: *const libc::c_char,
    ) -> libc::c_int;
    fn SSL_get_verify_result(ssl_0: *const SSL) -> libc::c_long;
    fn SSL_get_ex_data_X509_STORE_CTX_idx() -> libc::c_int;
    fn OPENSSL_init_ssl(
        opts: uint64_t,
        settings: *const OPENSSL_INIT_SETTINGS,
    ) -> libc::c_int;
    fn ERR_get_error_line_data(
        file: *mut *const libc::c_char,
        line: *mut libc::c_int,
        data: *mut *const libc::c_char,
        flags: *mut libc::c_int,
    ) -> libc::c_ulong;
    fn ERR_reason_error_string(e: libc::c_ulong) -> *const libc::c_char;
    fn RAND_set_rand_engine(engine: *mut ENGINE) -> libc::c_int;
    fn X509_STORE_CTX_get_current_cert(ctx_0: *mut X509_STORE_CTX) -> *mut X509;
    fn X509_STORE_CTX_get_ex_data(
        ctx_0: *mut X509_STORE_CTX,
        idx: libc::c_int,
    ) -> *mut libc::c_void;
    fn X509_STORE_CTX_get_error(ctx_0: *mut X509_STORE_CTX) -> libc::c_int;
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
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
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
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type u_int32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
pub type __fd_mask = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fd_set {
    pub __fds_bits: [__fd_mask; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct option {
    pub name: *const libc::c_char,
    pub has_arg: libc::c_int,
    pub flag: *mut libc::c_int,
    pub val: libc::c_int,
}
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub __pad0: libc::c_int,
    pub _sifields: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_8,
    pub _timer: C2RustUnnamed_7,
    pub _rt: C2RustUnnamed_6,
    pub _sigchld: C2RustUnnamed_5,
    pub _sigfault: C2RustUnnamed_2,
    pub _sigpoll: C2RustUnnamed_1,
    pub _sigsys: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub _addr_bnd: C2RustUnnamed_4,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option::<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_9,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option::<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction: Option::<
        unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> (),
    >,
}
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
pub type C2RustUnnamed_10 = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed_10 = 2;
pub const SHUT_WR: C2RustUnnamed_10 = 1;
pub const SHUT_RD: C2RustUnnamed_10 = 0;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_11,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
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
pub type X509 = x509_st;
pub type X509_NAME = X509_name_st;
pub type X509_STORE_CTX = x509_store_ctx_st;
pub type OPENSSL_INIT_SETTINGS = ossl_init_settings_st;
pub type ENGINE = engine_st;
pub type SSL = ssl_st;
pub type SSL_CTX = ssl_ctx_st;
pub type SSL_METHOD = ssl_method_st;
pub type SSL_CIPHER = ssl_cipher_st;
pub type SSL_verify_cb = Option::<
    unsafe extern "C" fn(libc::c_int, *mut X509_STORE_CTX) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _v2_packet {
    pub packet_version: int16_t,
    pub packet_type: int16_t,
    pub crc32_value: u_int32_t,
    pub result_code: int16_t,
    pub buffer: [libc::c_char; 1024],
}
pub type v2_packet = _v2_packet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _v3_packet {
    pub packet_version: int16_t,
    pub packet_type: int16_t,
    pub crc32_value: u_int32_t,
    pub result_code: int16_t,
    pub alignment: int16_t,
    pub buffer_length: int32_t,
    pub buffer: [libc::c_char; 1],
}
pub type v3_packet = _v3_packet;
pub type _SSL_VER = libc::c_uint;
pub const TLSv1_3_plus: _SSL_VER = 12;
pub const TLSv1_3: _SSL_VER = 11;
pub const TLSv1_2_plus: _SSL_VER = 10;
pub const TLSv1_2: _SSL_VER = 9;
pub const TLSv1_1_plus: _SSL_VER = 8;
pub const TLSv1_1: _SSL_VER = 7;
pub const TLSv1_plus: _SSL_VER = 6;
pub const TLSv1: _SSL_VER = 5;
pub const SSLv3_plus: _SSL_VER = 4;
pub const SSLv3: _SSL_VER = 3;
pub const SSLv2_plus: _SSL_VER = 2;
pub const SSLv2: _SSL_VER = 1;
pub const SSL_Ver_Invalid: _SSL_VER = 0;
pub type SslVer = _SSL_VER;
pub type _CLNT_CERTS = libc::c_uint;
pub const Require_Cert: _CLNT_CERTS = 2;
pub const Ask_For_Cert: _CLNT_CERTS = 1;
pub type ClntCerts = _CLNT_CERTS;
pub type _SSL_LOGGING = libc::c_uint;
pub const SSL_LogCertDetails: _SSL_LOGGING = 32;
pub const SSL_LogIfClientCert: _SSL_LOGGING = 16;
pub const SSL_LogCipher: _SSL_LOGGING = 8;
pub const SSL_LogVersion: _SSL_LOGGING = 4;
pub const SSL_LogIpAddr: _SSL_LOGGING = 2;
pub const SSL_LogStartup: _SSL_LOGGING = 1;
pub const SSL_NoLogging: _SSL_LOGGING = 0;
pub type SslLogging = _SSL_LOGGING;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _SSL_PARMS {
    pub cert_file: *mut libc::c_char,
    pub cacert_file: *mut libc::c_char,
    pub privatekey_file: *mut libc::c_char,
    pub cipher_list: [libc::c_char; 256],
    pub ssl_proto_ver: SslVer,
    pub allowDH: libc::c_int,
    pub client_certs: ClntCerts,
    pub log_opts: SslLogging,
}
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as libc::c_int;
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[inline]
unsafe extern "C" fn stat(
    mut __path: *const libc::c_char,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __xstat(1 as libc::c_int, __path, __statbuf);
}
#[inline]
unsafe extern "C" fn fstat(
    mut __fd: libc::c_int,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __fxstat(1 as libc::c_int, __fd, __statbuf);
}
#[no_mangle]
pub static mut server_port: u_short = 0 as libc::c_int as u_short;
#[no_mangle]
pub static mut server_name: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut bind_address: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut config_file: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut hostaddr: sockaddr_storage = sockaddr_storage {
    ss_family: 0,
    __ss_padding: [0; 118],
    __ss_align: 0,
};
#[no_mangle]
pub static mut address_family: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut command_name: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut socket_timeout: libc::c_int = 10 as libc::c_int;
#[no_mangle]
pub static mut timeout_txt: [libc::c_char; 10] = [0; 10];
#[no_mangle]
pub static mut timeout_return_code: libc::c_int = -(1 as libc::c_int);
#[no_mangle]
pub static mut stderr_to_stdout: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut sd: libc::c_int = 0;
#[no_mangle]
pub static mut rem_host: [libc::c_char; 256] = [0; 256];
#[no_mangle]
pub static mut query: [libc::c_char; 2048] = unsafe {
    *::core::mem::transmute::<
        &[u8; 2048],
        &mut [libc::c_char; 2048],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
};
#[no_mangle]
pub static mut show_help: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut show_license: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut show_version: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut packet_ver: libc::c_int = 4 as libc::c_int;
#[no_mangle]
pub static mut force_v2_packet: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut force_v3_packet: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut payload_size: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut meth: *const SSL_METHOD = 0 as *const SSL_METHOD;
#[no_mangle]
pub static mut ctx: *mut SSL_CTX = 0 as *const SSL_CTX as *mut SSL_CTX;
#[no_mangle]
pub static mut ssl: *mut SSL = 0 as *const SSL as *mut SSL;
#[no_mangle]
pub static mut use_ssl: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut ssl_opts: libc::c_ulong = (0x80000000 as libc::c_uint
    | 0x800 as libc::c_uint | 0x4 as libc::c_uint | 0x10 as libc::c_uint
    | 0x40 as libc::c_uint) as libc::c_ulong;
#[no_mangle]
pub static mut sslprm: _SSL_PARMS = unsafe {
    {
        let mut init = _SSL_PARMS {
            cert_file: 0 as *const libc::c_char as *mut libc::c_char,
            cacert_file: 0 as *const libc::c_char as *mut libc::c_char,
            privatekey_file: 0 as *const libc::c_char as *mut libc::c_char,
            cipher_list: *::core::mem::transmute::<
                &[u8; 256],
                &mut [libc::c_char; 256],
            >(
                b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            ),
            ssl_proto_ver: SSL_Ver_Invalid,
            allowDH: -(1 as libc::c_int),
            client_certs: 0 as ClntCerts,
            log_opts: SSL_NoLogging,
        };
        init
    }
};
#[no_mangle]
pub static mut have_log_opts: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut disable_syslog: libc::c_int = 0 as libc::c_int;
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
    mut hostaddr_0: *mut sockaddr_storage,
    mut port: u_short,
    mut address_family_0: libc::c_int,
    mut bind_address_0: *const libc::c_char,
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
    hints.ai_family = address_family_0;
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
                sock = my_create_socket(ai, bind_address_0, redirect_stderr);
                if !(sock < 0 as libc::c_int) {
                    if connect(sock, (*ai).ai_addr, (*ai).ai_addrlen) >= 0 as libc::c_int
                    {
                        memcpy(
                            hostaddr_0 as *mut libc::c_void,
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
    mut bind_address_0: *const libc::c_char,
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
    if bind_address_0.is_null() {
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
    gaierr = getaddrinfo(bind_address_0, 0 as *const libc::c_char, &mut hints, &mut res);
    if gaierr != 0 {
        fprintf(
            output,
            b"getaddrinfo: %s: %s\n\0" as *const u8 as *const libc::c_char,
            bind_address_0,
            gai_strerror(gaierr),
        );
        close(sock);
        return -(1 as libc::c_int);
    }
    if bind(sock, (*res).ai_addr, (*res).ai_addrlen) < 0 as libc::c_int {
        fprintf(
            output,
            b"bind: %s: %s\n\0" as *const u8 as *const libc::c_char,
            bind_address_0,
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
    mut address_family_0: libc::c_int,
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
    hints.ai_family = address_family_0;
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
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut result: int16_t = 0;
    result = process_arguments(argc, argv, 0 as libc::c_int) as int16_t;
    if result as libc::c_int != 0 as libc::c_int || show_help == 1 as libc::c_int
        || show_license == 1 as libc::c_int || show_version == 1 as libc::c_int
    {
        usage(result as libc::c_int);
    }
    snprintf(
        timeout_txt.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 10]>() as libc::c_ulong,
        b"%d\0" as *const u8 as *const libc::c_char,
        socket_timeout,
    );
    if server_port as libc::c_int == 0 as libc::c_int {
        server_port = 5666 as libc::c_int as u_short;
    }
    if socket_timeout == -(1 as libc::c_int) {
        socket_timeout = 10 as libc::c_int;
    }
    if timeout_return_code == -(1 as libc::c_int) {
        timeout_return_code = 2 as libc::c_int;
    }
    if sslprm.cipher_list[0 as libc::c_int as usize] as libc::c_int == '\0' as i32 {
        strncpy(
            (sslprm.cipher_list).as_mut_ptr(),
            b"ALL:!MD5:@STRENGTH:@SECLEVEL=0\0" as *const u8 as *const libc::c_char,
            (256 as libc::c_int - 1 as libc::c_int) as libc::c_ulong,
        );
    }
    if sslprm.ssl_proto_ver as libc::c_uint
        == SSL_Ver_Invalid as libc::c_int as libc::c_uint
    {
        sslprm.ssl_proto_ver = TLSv1_plus;
    }
    if sslprm.allowDH == -(1 as libc::c_int) {
        sslprm.allowDH = 1 as libc::c_int;
    }
    generate_crc32_table();
    setup_ssl();
    set_sig_handlers();
    result = connect_to_remote() as int16_t;
    if result as libc::c_int != 0 as libc::c_int {
        alarm(0 as libc::c_int as libc::c_uint);
        return result as libc::c_int;
    }
    result = send_request() as int16_t;
    if result as libc::c_int != 0 as libc::c_int {
        return result as libc::c_int;
    }
    result = read_response() as int16_t;
    if result as libc::c_int == -(1 as libc::c_int) {
        logit(
            6 as libc::c_int,
            b"Remote %s does not support version 3/4 packets\0" as *const u8
                as *const libc::c_char,
            rem_host.as_mut_ptr(),
        );
        packet_ver = 2 as libc::c_int;
        setup_ssl();
        set_sig_handlers();
        result = connect_to_remote() as int16_t;
        if result as libc::c_int != 0 as libc::c_int {
            alarm(0 as libc::c_int as libc::c_uint);
            close_log_file();
            return result as libc::c_int;
        }
        result = send_request() as int16_t;
        if result as libc::c_int != 0 as libc::c_int {
            close_log_file();
            return result as libc::c_int;
        }
        result = read_response() as int16_t;
    }
    if result as libc::c_int != -(1 as libc::c_int)
        && force_v2_packet == 0 as libc::c_int && packet_ver == 2 as libc::c_int
    {
        logit(
            7 as libc::c_int,
            b"Remote %s accepted a version %d packet\0" as *const u8
                as *const libc::c_char,
            rem_host.as_mut_ptr(),
            packet_ver,
        );
    }
    close_log_file();
    return result as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn process_arguments(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
    mut from_config_file: libc::c_int,
) -> libc::c_int {
    let mut optchars: [libc::c_char; 2048] = [0; 2048];
    let mut argindex: libc::c_int = 0 as libc::c_int;
    let mut c: libc::c_int = 1 as libc::c_int;
    let mut i: libc::c_int = 1 as libc::c_int;
    let mut has_cert: libc::c_int = 0 as libc::c_int;
    let mut has_priv_key: libc::c_int = 0 as libc::c_int;
    let mut rc: libc::c_int = 0;
    let mut option_index: libc::c_int = 0 as libc::c_int;
    static mut long_options: [option; 28] = [
        {
            let mut init = option {
                name: b"host\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'H' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"config-file\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'f' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"bind\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'b' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"command\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'c' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"args\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'a' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"no-ssl\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'n' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"unknown-timeout\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'u' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"v2-packets-only\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: '2' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"v3-packets-only\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: '3' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"ipv4\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: '4' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"ipv6\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: '6' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"use-adh\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'd' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"ssl-version\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'S' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"cipher-list\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'L' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"client-cert\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'C' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"key-file\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'K' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"ca-cert-file\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'A' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"ssl-logging\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 's' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"timeout\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 't' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"port\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'p' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"payload-size\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'P' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"log-file\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'g' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"help\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'h' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"license\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'l' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"version\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'V' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"stderr-to-stdout\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'E' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"disable-syslog\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'D' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: 0 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 0 as libc::c_int,
            };
            init
        },
    ];
    if argc < 2 as libc::c_int {
        return -(1 as libc::c_int);
    }
    optind = 0 as libc::c_int;
    snprintf(
        optchars.as_mut_ptr(),
        2048 as libc::c_int as libc::c_ulong,
        b"H:f:b:c:a:t:p:S:L:C:K:A:d:s:P:g:2346hlnuVED\0" as *const u8
            as *const libc::c_char,
    );
    while !(argindex > 0 as libc::c_int) {
        c = getopt_long(
            argc,
            argv,
            optchars.as_mut_ptr(),
            long_options.as_mut_ptr(),
            &mut option_index,
        );
        if c == -(1 as libc::c_int) || c == -(1 as libc::c_int) {
            break;
        }
        match c {
            63 | 104 => {
                show_help = 1 as libc::c_int;
            }
            98 => {
                bind_address = strdup(optarg);
            }
            102 => {
                if from_config_file != 0 {
                    printf(
                        b"Error: The config file should not have a config-file (-f) option.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    config_file = strdup(optarg);
                }
            }
            86 => {
                show_version = 1 as libc::c_int;
            }
            108 => {
                show_license = 1 as libc::c_int;
            }
            116 => {
                if from_config_file != 0 && socket_timeout != -(1 as libc::c_int) {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line socket timeout overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    socket_timeout = parse_timeout_string(optarg);
                    if socket_timeout <= 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                }
            }
            112 => {
                if from_config_file != 0
                    && server_port as libc::c_int != 0 as libc::c_int
                {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line server port overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    server_port = atoi(optarg) as u_short;
                    if server_port as libc::c_int <= 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                }
            }
            80 => {
                if from_config_file != 0 && payload_size > 0 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line payload-size (-P) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    payload_size = atoi(optarg);
                    if payload_size < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                }
            }
            72 => {
                if from_config_file != 0 && !server_name.is_null() {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line server name overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    server_name = strdup(optarg);
                }
            }
            69 => {
                if from_config_file != 0 && stderr_to_stdout != 0 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line stderr redirection overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    stderr_to_stdout = 1 as libc::c_int;
                }
            }
            99 => {
                if from_config_file != 0 {
                    printf(
                        b"Error: The config file should not have a command (-c) option.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                command_name = strdup(optarg);
            }
            97 => {
                if from_config_file != 0 {
                    printf(
                        b"Error: The config file should not have args (-a) arguments.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
                argindex = optind;
            }
            110 => {
                use_ssl = 0 as libc::c_int;
            }
            117 => {
                if from_config_file != 0 && timeout_return_code != -(1 as libc::c_int) {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line unknown-timeout (-u) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    timeout_return_code = 3 as libc::c_int;
                }
            }
            50 => {
                if from_config_file != 0 && packet_ver != 4 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line v2-packets-only (-2) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    packet_ver = 2 as libc::c_int;
                    force_v2_packet = 1 as libc::c_int;
                }
            }
            51 => {
                if from_config_file != 0 && packet_ver != 4 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"Warning: Command-line v3-packets-only (-3) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    packet_ver = 3 as libc::c_int;
                    force_v3_packet = 1 as libc::c_int;
                }
            }
            52 => {
                if from_config_file != 0 && address_family != 0 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line ipv4 (-4) or ipv6 (-6) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    address_family = 2 as libc::c_int;
                }
            }
            54 => {
                if from_config_file != 0 && address_family != 0 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line ipv4 (-4) or ipv6 (-6) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    address_family = 10 as libc::c_int;
                }
            }
            100 => {
                if from_config_file != 0 && sslprm.allowDH != -(1 as libc::c_int) {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line use-adh (-d) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    if optarg.is_null()
                        || (*optarg.offset(0 as libc::c_int as isize) as libc::c_int)
                            < '0' as i32
                        || *optarg.offset(0 as libc::c_int as isize) as libc::c_int
                            > '2' as i32
                    {
                        return -(1 as libc::c_int);
                    }
                    sslprm.allowDH = atoi(optarg);
                }
            }
            65 => {
                if from_config_file != 0 && !(sslprm.cacert_file).is_null() {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line ca-cert-file (-A) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    sslprm.cacert_file = strdup(optarg);
                }
            }
            67 => {
                if from_config_file != 0 && !(sslprm.cert_file).is_null() {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line client-cert (-C) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    sslprm.cert_file = strdup(optarg);
                    has_cert = 1 as libc::c_int;
                }
            }
            75 => {
                if from_config_file != 0 && !(sslprm.privatekey_file).is_null() {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line key-file (-K) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    sslprm.privatekey_file = strdup(optarg);
                    has_priv_key = 1 as libc::c_int;
                }
            }
            83 => {
                if from_config_file != 0
                    && sslprm.ssl_proto_ver as libc::c_uint
                        != SSL_Ver_Invalid as libc::c_int as libc::c_uint
                {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line ssl-version (-S) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else if strcmp(
                    optarg,
                    b"TLSv1.3\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_3;
                } else if strcmp(
                    optarg,
                    b"TLSv1.3+\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_3_plus;
                } else if strcmp(
                    optarg,
                    b"TLSv1.2\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_2;
                } else if strcmp(
                    optarg,
                    b"TLSv1.2+\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_2_plus;
                } else if strcmp(
                    optarg,
                    b"TLSv1.1\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_1;
                } else if strcmp(
                    optarg,
                    b"TLSv1.1+\0" as *const u8 as *const libc::c_char,
                ) == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_1_plus;
                } else if strcmp(optarg, b"TLSv1\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    sslprm.ssl_proto_ver = TLSv1;
                } else if strcmp(optarg, b"TLSv1+\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    sslprm.ssl_proto_ver = TLSv1_plus;
                } else if strcmp(optarg, b"SSLv3\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    sslprm.ssl_proto_ver = SSLv3;
                } else if strcmp(optarg, b"SSLv3+\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    sslprm.ssl_proto_ver = SSLv3_plus;
                } else {
                    return -(1 as libc::c_int)
                }
            }
            76 => {
                if from_config_file != 0
                    && sslprm.cipher_list[0 as libc::c_int as usize] as libc::c_int
                        != '\0' as i32
                {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line cipher-list (-L) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    strncpy(
                        (sslprm.cipher_list).as_mut_ptr(),
                        optarg,
                        (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                    sslprm
                        .cipher_list[(::core::mem::size_of::<[libc::c_char; 256]>()
                        as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as usize] = '\0' as i32 as libc::c_char;
                }
            }
            115 => {
                if from_config_file != 0 && have_log_opts == 1 as libc::c_int {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line ssl-logging (-s) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    sslprm
                        .log_opts = strtoul(
                        optarg,
                        0 as *mut *mut libc::c_char,
                        0 as libc::c_int,
                    ) as SslLogging;
                    have_log_opts = 1 as libc::c_int;
                }
            }
            103 => {
                if from_config_file != 0 && !log_file.is_null() {
                    logit(
                        4 as libc::c_int,
                        b"WARNING: Command-line log-file (-g) overrides the config file option.\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    log_file = strdup(optarg);
                    open_log_file();
                }
            }
            68 => {
                disable_syslog = 1 as libc::c_int;
            }
            _ => return -(1 as libc::c_int),
        }
    }
    if from_config_file == 0 {
        snprintf(
            query.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
            b"%s\0" as *const u8 as *const libc::c_char,
            if command_name.is_null() {
                b"_NRPE_CHECK\0" as *const u8 as *const libc::c_char
            } else {
                command_name as *const libc::c_char
            },
        );
        query[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
    }
    if from_config_file == 0 && argindex > 0 as libc::c_int {
        c = argindex - 1 as libc::c_int;
        while c < argc {
            i = (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(strlen(query.as_mut_ptr()))
                .wrapping_sub(2 as libc::c_int as libc::c_ulong) as libc::c_int;
            if i <= 0 as libc::c_int {
                break;
            }
            strcat(query.as_mut_ptr(), b"!\0" as *const u8 as *const libc::c_char);
            strncat(query.as_mut_ptr(), *argv.offset(c as isize), i as libc::c_ulong);
            query[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
            c += 1;
        }
    }
    if from_config_file == 0 && !config_file.is_null() {
        rc = read_config_file(config_file);
        if rc != 0 as libc::c_int {
            return rc;
        }
    }
    if has_cert != 0 && has_priv_key == 0 || has_cert == 0 && has_priv_key != 0 {
        printf(
            b"Error: the client certificate and the private key must both be given or neither\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if payload_size > 0 as libc::c_int && packet_ver != 2 as libc::c_int {
        printf(
            b"Error: if a fixed payload size is specified, '-2' must also be specified\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if force_v2_packet != 0 && force_v3_packet != 0 {
        printf(
            b"Error: Only one of force_v2_packet (-2) and force_v3_packet (-3) can be specified.\n\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if server_name.is_null() && show_help == 0 as libc::c_int
        && show_version == 0 as libc::c_int && show_license == 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn read_config_file(mut fname: *mut libc::c_char) -> libc::c_int {
    let mut rc: libc::c_int = 0;
    let mut argc: libc::c_int = 0 as libc::c_int;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut bufp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut argv: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut delims: *mut libc::c_char = b" \t\r\n\0" as *const u8 as *const libc::c_char
        as *mut libc::c_char;
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
    let mut sz: size_t = 0;
    if stat(fname, &mut st) != 0 {
        logit(
            3 as libc::c_int,
            b"Error: Could not stat config file %s\0" as *const u8
                as *const libc::c_char,
            fname,
        );
        return -(1 as libc::c_int);
    }
    f = fopen(fname, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        logit(
            3 as libc::c_int,
            b"Error: Could not open config file %s\0" as *const u8
                as *const libc::c_char,
            fname,
        );
        return -(1 as libc::c_int);
    }
    buf = calloc(
        1 as libc::c_int as libc::c_ulong,
        (st.st_size + 2 as libc::c_int as libc::c_long) as libc::c_ulong,
    ) as *mut libc::c_char;
    if buf.is_null() {
        fclose(f);
        logit(
            3 as libc::c_int,
            b"Error: read_config_file fail to allocate memory\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    sz = fread(
        buf as *mut libc::c_void,
        1 as libc::c_int as libc::c_ulong,
        st.st_size as libc::c_ulong,
        f,
    );
    if sz != st.st_size as libc::c_ulong {
        fclose(f);
        free(buf as *mut libc::c_void);
        logit(
            3 as libc::c_int,
            b"Error: Failed to completely read config file %s\0" as *const u8
                as *const libc::c_char,
            fname,
        );
        return -(1 as libc::c_int);
    }
    argv = calloc(
        50 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if argv.is_null() {
        fclose(f);
        free(buf as *mut libc::c_void);
        logit(
            3 as libc::c_int,
            b"Error: read_config_file fail to allocate memory\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    let fresh4 = argc;
    argc = argc + 1;
    let ref mut fresh5 = *argv.offset(fresh4 as isize);
    *fresh5 = b"check_nrpe\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    bufp = buf;
    while argc < 50 as libc::c_int {
        while *bufp as libc::c_int != 0
            && !(strchr(delims, *bufp as libc::c_int)).is_null()
        {
            bufp = bufp.offset(1);
        }
        if *bufp as libc::c_int == '\0' as i32 {
            break;
        }
        let ref mut fresh6 = *argv.offset(argc as isize);
        *fresh6 = my_strsep(&mut bufp, delims);
        let fresh7 = argc;
        argc = argc + 1;
        if (*argv.offset(fresh7 as isize)).is_null() {
            break;
        }
        if bufp.is_null() {
            break;
        }
    }
    fclose(f);
    if argc == 50 as libc::c_int {
        free(buf as *mut libc::c_void);
        free(argv as *mut libc::c_void);
        logit(
            3 as libc::c_int,
            b"Error: too many parameters in config file %s\0" as *const u8
                as *const libc::c_char,
            fname,
        );
        return -(1 as libc::c_int);
    }
    rc = process_arguments(argc, argv, 1 as libc::c_int);
    free(buf as *mut libc::c_void);
    free(argv as *mut libc::c_void);
    return rc;
}
#[no_mangle]
pub unsafe extern "C" fn state_text(mut result: libc::c_int) -> *const libc::c_char {
    match result {
        0 => return b"OK\0" as *const u8 as *const libc::c_char,
        1 => return b"WARNING\0" as *const u8 as *const libc::c_char,
        2 => return b"CRITICAL\0" as *const u8 as *const libc::c_char,
        _ => return b"UNKNOWN\0" as *const u8 as *const libc::c_char,
    };
}
#[no_mangle]
pub unsafe extern "C" fn translate_state(
    mut state_text_0: *mut libc::c_char,
) -> libc::c_int {
    if strcasecmp(state_text_0, b"OK\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(state_text_0, b"0\0" as *const u8 as *const libc::c_char) == 0
    {
        return 0 as libc::c_int;
    }
    if strcasecmp(state_text_0, b"WARNING\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(state_text_0, b"1\0" as *const u8 as *const libc::c_char) == 0
    {
        return 1 as libc::c_int;
    }
    if strcasecmp(state_text_0, b"CRITICAL\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(state_text_0, b"2\0" as *const u8 as *const libc::c_char) == 0
    {
        return 2 as libc::c_int;
    }
    if strcasecmp(state_text_0, b"UNKNOWN\0" as *const u8 as *const libc::c_char) == 0
        || strcmp(state_text_0, b"3\0" as *const u8 as *const libc::c_char) == 0
    {
        return 3 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn set_timeout_state(mut state: *mut libc::c_char) {
    timeout_return_code = translate_state(state);
    if timeout_return_code == -(1 as libc::c_int) {
        printf(
            b"Timeout state must be a valid state name (OK, WARNING, CRITICAL, UNKNOWN) or integer (0-3).\n\0"
                as *const u8 as *const libc::c_char,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn parse_timeout_string(
    mut timeout_str: *mut libc::c_char,
) -> libc::c_int {
    let mut separated_str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut timeout_val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut timeout_sta: *mut libc::c_char = 0 as *mut libc::c_char;
    if (strstr(timeout_str, b":\0" as *const u8 as *const libc::c_char)).is_null() {
        timeout_val = timeout_str;
    } else if strncmp(
        timeout_str,
        b":\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        separated_str = strtok(timeout_str, b":\0" as *const u8 as *const libc::c_char);
        if !separated_str.is_null() {
            timeout_sta = separated_str;
        }
    } else {
        separated_str = strtok(timeout_str, b":\0" as *const u8 as *const libc::c_char);
        timeout_val = separated_str;
        separated_str = strtok(
            0 as *mut libc::c_char,
            b":\0" as *const u8 as *const libc::c_char,
        );
        if !separated_str.is_null() {
            timeout_sta = separated_str;
        }
    }
    if !timeout_sta.is_null() {
        set_timeout_state(timeout_sta);
    }
    if timeout_val.is_null()
        || *timeout_val.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32
    {
        return socket_timeout
    } else if atoi(timeout_val) > 0 as libc::c_int {
        return atoi(timeout_val)
    } else {
        printf(
            b"Timeout value must be a positive integer\n\0" as *const u8
                as *const libc::c_char,
        );
        exit(3 as libc::c_int);
    };
}
#[no_mangle]
pub unsafe extern "C" fn usage(mut result: libc::c_int) {
    if result != 0 as libc::c_int {
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"Incorrect command line arguments supplied\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
    printf(b"NRPE Plugin for Nagios\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"Version: %s\n\0" as *const u8 as *const libc::c_char,
        b"4.1.0\0" as *const u8 as *const libc::c_char,
    );
    printf(b"\n\0" as *const u8 as *const libc::c_char);
    if result != 0 as libc::c_int || show_help == 1 as libc::c_int {
        printf(
            b"Copyright (c) 2009-2017 Nagios Enterprises\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"              1999-2008 Ethan Galstad (nagios@nagios.org)\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"Last Modified: %s\n\0" as *const u8 as *const libc::c_char,
            b"2022-07-18\0" as *const u8 as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"License: GPL v2 with exemptions (-l for more info)\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"SSL/TLS Available: OpenSSL 0.9.6 or higher required\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"Usage: check_nrpe -H <host> [-2] [-3] [-4] [-6] [-n] [-u] [-V] [-l] [-d <dhopt>]\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"       [-P <size>] [-S <ssl version>]  [-L <cipherlist>] [-C <clientcert>]\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"       [-K <key>] [-A <ca-certificate>] [-s <logopts>] [-b <bindaddr>]\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"       [-f <cfg-file>] [-p <port>] [-t <interval>:<state>] [-g <log-file>]\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"       [-c <command>] [-E] [-D] [-a <arglist...>]\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(b"Options:\n\0" as *const u8 as *const libc::c_char);
        printf(
            b" -H, --host=HOST              The address of the host running the NRPE daemon\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -2, --v2-packets-only        Only use version 2 packets, not version 3/4\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -3, --v3-packets-only        Only use version 3 packets, not version 4\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -4, --ipv4                   Bind to ipv4 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -6, --ipv6                   Bind to ipv6 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -n, --no-ssl                 Do no use SSL\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -u, --unknown-timeout        Make connection problems return UNKNOWN instead of CRITICAL\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -V, --version                Print version info and quit\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -l, --license                Show license\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -E, --stderr-to-stdout       Redirect stderr to stdout\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -d, --use-adh=DHOPT          Anonymous Diffie Hellman use:\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              0         Don't use Anonymous Diffie Hellman\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                                        (This will be the default in a future release.)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              1         Allow Anonymous Diffie Hellman (default)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              2         Force Anonymous Diffie Hellman\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -D, --disable-syslog         Disable logging to syslog facilities\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -P, --payload-size=SIZE      Specify non-default payload size for NSClient++\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -S, --ssl-version=VERSION    The SSL/TLS version to use. Can be any one of:\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              SSLv3     SSL v3 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              SSLv3+    SSL v3 or above \n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              TLSv1     TLS v1 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              TLSv1+    TLS v1 or above (DEFAULT)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              TLSv1.1   TLS v1.1 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              TLSv1.1+  TLS v1.1 or above\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              TLSv1.2   TLS v1.2 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"                              TLSv1.2+  TLS v1.2 or above\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -L, --cipher-list=LIST       The list of SSL ciphers to use (currently defaults\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              to \"ALL:!MD5:@STRENGTH:@SECLEVEL=0\". THIS WILL change in a future release.)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -C, --client-cert=FILE       The client certificate to use for PKI\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -K, --key-file=FILE          The private key to use with the client certificate\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -A, --ca-cert-file=FILE      The CA certificate to use for PKI\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -s, --ssl-logging=OPTIONS    SSL Logging Options\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -b, --bind=IPADDR            Local address to bind to\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -f, --config-file=FILE       Configuration file to use\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -g, --log-file=FILE          Log file to write to\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -p, --port=PORT              The port on which the daemon is running (default=%d)\n\0"
                as *const u8 as *const libc::c_char,
            5666 as libc::c_int,
        );
        printf(
            b" -c, --command=COMMAND        The name of the command that the remote daemon should run\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -a, --args=LIST              Optional arguments that should be passed to the command,\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              separated by a space. If provided, this must be the last\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              option supplied on the command line.\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b" -e \t                      Enable syslog debug messages.\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(b" NEW TIMEOUT SYNTAX\n\0" as *const u8 as *const libc::c_char);
        printf(b" -t, --timeout=INTERVAL:STATE\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"                              INTERVAL  Number of seconds before connection times out (default=%d)\n\0"
                as *const u8 as *const libc::c_char,
            10 as libc::c_int,
        );
        printf(
            b"                              STATE     Check state to exit with in the event of a timeout (default=CRITICAL)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              Timeout STATE must be a valid state name (case-insensitive) or integer:\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"                              (OK, WARNING, CRITICAL, UNKNOWN) or integer (0-3)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(b"Note:\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"This plugin requires that you have the NRPE daemon running on the remote host.\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"You must also have configured the daemon to associate a specific plugin command\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"with the [command] option you are specifying here. Upon receipt of the\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"[command] argument, the NRPE daemon will run the appropriate plugin command and\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"send the plugin output and return code back to *this* plugin. This allows you\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"to execute plugins on remote hosts and 'fake' the results to make Nagios think\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"the plugin is being run locally.\n\0" as *const u8 as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
    if show_license == 1 as libc::c_int {
        display_license();
    }
    exit(3 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn setup_ssl() {
    let mut vrfy: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    if sslprm.log_opts as libc::c_uint & SSL_LogStartup as libc::c_int as libc::c_uint
        != 0
    {
        let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
        logit(
            6 as libc::c_int,
            b"SSL Certificate File: %s\0" as *const u8 as *const libc::c_char,
            if !(sslprm.cert_file).is_null() {
                sslprm.cert_file as *const libc::c_char
            } else {
                b"None\0" as *const u8 as *const libc::c_char
            },
        );
        logit(
            6 as libc::c_int,
            b"SSL Private Key File: %s\0" as *const u8 as *const libc::c_char,
            if !(sslprm.privatekey_file).is_null() {
                sslprm.privatekey_file as *const libc::c_char
            } else {
                b"None\0" as *const u8 as *const libc::c_char
            },
        );
        logit(
            6 as libc::c_int,
            b"SSL CA Certificate File: %s\0" as *const u8 as *const libc::c_char,
            if !(sslprm.cacert_file).is_null() {
                sslprm.cacert_file as *const libc::c_char
            } else {
                b"None\0" as *const u8 as *const libc::c_char
            },
        );
        logit(
            6 as libc::c_int,
            b"SSL Cipher List: %s\0" as *const u8 as *const libc::c_char,
            (sslprm.cipher_list).as_mut_ptr(),
        );
        logit(
            6 as libc::c_int,
            b"SSL Allow ADH: %d\0" as *const u8 as *const libc::c_char,
            sslprm.allowDH,
        );
        logit(
            6 as libc::c_int,
            b"SSL Log Options: 0x%02x\0" as *const u8 as *const libc::c_char,
            sslprm.log_opts as libc::c_uint,
        );
        match sslprm.ssl_proto_ver as libc::c_uint {
            1 => {
                val = b"SSLv2\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            2 => {
                val = b"SSLv2 And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            3 => {
                val = b"SSLv3\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            4 => {
                val = b"SSLv3_plus And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            5 => {
                val = b"TLSv1\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            6 => {
                val = b"TLSv1_plus And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            7 => {
                val = b"TLSv1_1\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            8 => {
                val = b"TLSv1_1_plus And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            9 => {
                val = b"TLSv1_2\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            10 => {
                val = b"TLSv1_2_plus And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            11 => {
                val = b"TLSv1_3\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            12 => {
                val = b"TLSv1_3_plus And Above\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
            _ => {
                val = b"INVALID VALUE!\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
            }
        }
        logit(
            6 as libc::c_int,
            b"SSL Version: %s\0" as *const u8 as *const libc::c_char,
            val,
        );
    }
    if use_ssl == 1 as libc::c_int {
        OPENSSL_init_ssl(
            (0x200000 as libc::c_long | 0x2 as libc::c_long) as uint64_t,
            0 as *const OPENSSL_INIT_SETTINGS,
        );
        OPENSSL_init_ssl(
            0 as libc::c_int as uint64_t,
            0 as *const OPENSSL_INIT_SETTINGS,
        );
        ENGINE_load_builtin_engines();
        RAND_set_rand_engine(0 as *mut ENGINE);
        ENGINE_register_all_complete();
        meth = TLS_method();
        ctx = SSL_CTX_new(meth);
        if ctx.is_null() {
            printf(
                b"CHECK_NRPE: Error - could not create SSL context.\n\0" as *const u8
                    as *const libc::c_char,
            );
            exit(timeout_return_code);
        }
        SSL_CTX_ctrl(
            ctx,
            124 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            0 as *mut libc::c_void,
        );
        let mut current_block_43: u64;
        match sslprm.ssl_proto_ver as libc::c_uint {
            11 => {
                SSL_CTX_ctrl(
                    ctx,
                    124 as libc::c_int,
                    0x304 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
                current_block_43 = 17249410179350931503;
            }
            12 => {
                current_block_43 = 17249410179350931503;
            }
            9 => {
                SSL_CTX_ctrl(
                    ctx,
                    124 as libc::c_int,
                    0x303 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
                current_block_43 = 1082269060075641672;
            }
            10 => {
                current_block_43 = 1082269060075641672;
            }
            7 => {
                SSL_CTX_ctrl(
                    ctx,
                    124 as libc::c_int,
                    0x302 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
                current_block_43 = 2790445198151228770;
            }
            8 => {
                current_block_43 = 2790445198151228770;
            }
            5 => {
                SSL_CTX_ctrl(
                    ctx,
                    124 as libc::c_int,
                    0x301 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
                current_block_43 = 2152508036044900888;
            }
            6 => {
                current_block_43 = 2152508036044900888;
            }
            3 => {
                SSL_CTX_ctrl(
                    ctx,
                    124 as libc::c_int,
                    0x300 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
                current_block_43 = 7691958333613135882;
            }
            4 => {
                current_block_43 = 7691958333613135882;
            }
            _ => {
                current_block_43 = 2122094917359643297;
            }
        }
        match current_block_43 {
            17249410179350931503 => {
                SSL_CTX_ctrl(
                    ctx,
                    123 as libc::c_int,
                    0x304 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
            }
            1082269060075641672 => {
                SSL_CTX_ctrl(
                    ctx,
                    123 as libc::c_int,
                    0x303 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
            }
            2790445198151228770 => {
                SSL_CTX_ctrl(
                    ctx,
                    123 as libc::c_int,
                    0x302 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
            }
            2152508036044900888 => {
                SSL_CTX_ctrl(
                    ctx,
                    123 as libc::c_int,
                    0x301 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
            }
            7691958333613135882 => {
                SSL_CTX_ctrl(
                    ctx,
                    123 as libc::c_int,
                    0x300 as libc::c_int as libc::c_long,
                    0 as *mut libc::c_void,
                );
            }
            _ => {}
        }
        SSL_CTX_set_options(ctx, ssl_opts);
        if !(sslprm.cert_file).is_null() && !(sslprm.privatekey_file).is_null() {
            if SSL_CTX_use_certificate_chain_file(ctx, sslprm.cert_file) == 0 {
                printf(
                    b"Error: could not use certificate file '%s'.\n\0" as *const u8
                        as *const libc::c_char,
                    sslprm.cert_file,
                );
                loop {
                    x = ERR_get_error_line_data(
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                    ) as libc::c_int;
                    if !(x != 0 as libc::c_int) {
                        break;
                    }
                    printf(
                        b"Error: could not use certificate file '%s': %s\n\0"
                            as *const u8 as *const libc::c_char,
                        sslprm.cert_file,
                        ERR_reason_error_string(x as libc::c_ulong),
                    );
                }
                SSL_CTX_free(ctx);
                exit(timeout_return_code);
            }
            if SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, 1 as libc::c_int)
                == 0
            {
                SSL_CTX_free(ctx);
                printf(
                    b"Error: could not use private key file '%s'.\n\0" as *const u8
                        as *const libc::c_char,
                    sslprm.privatekey_file,
                );
                loop {
                    x = ERR_get_error_line_data(
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                    ) as libc::c_int;
                    if !(x != 0 as libc::c_int) {
                        break;
                    }
                    printf(
                        b"Error: could not use private key file '%s': %s\n\0"
                            as *const u8 as *const libc::c_char,
                        sslprm.privatekey_file,
                        ERR_reason_error_string(x as libc::c_ulong),
                    );
                }
                SSL_CTX_free(ctx);
                exit(timeout_return_code);
            }
        }
        if !(sslprm.cacert_file).is_null() {
            vrfy = 0x1 as libc::c_int | 0x2 as libc::c_int;
            SSL_CTX_set_verify(
                ctx,
                vrfy,
                Some(
                    verify_callback
                        as unsafe extern "C" fn(
                            libc::c_int,
                            *mut X509_STORE_CTX,
                        ) -> libc::c_int,
                ),
            );
            if SSL_CTX_load_verify_locations(
                ctx,
                sslprm.cacert_file,
                0 as *const libc::c_char,
            ) == 0
            {
                printf(
                    b"Error: could not use CA certificate '%s'.\n\0" as *const u8
                        as *const libc::c_char,
                    sslprm.cacert_file,
                );
                loop {
                    x = ERR_get_error_line_data(
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                        0 as *mut *const libc::c_char,
                        0 as *mut libc::c_int,
                    ) as libc::c_int;
                    if !(x != 0 as libc::c_int) {
                        break;
                    }
                    printf(
                        b"Error: could not use CA certificate '%s': %s\n\0" as *const u8
                            as *const libc::c_char,
                        sslprm.privatekey_file,
                        ERR_reason_error_string(x as libc::c_ulong),
                    );
                }
                SSL_CTX_free(ctx);
                exit(timeout_return_code);
            }
        }
        if sslprm.allowDH == 0 {
            if strlen((sslprm.cipher_list).as_mut_ptr())
                < (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    .wrapping_sub(6 as libc::c_int as libc::c_ulong)
            {
                strcat(
                    (sslprm.cipher_list).as_mut_ptr(),
                    b":!ADH\0" as *const u8 as *const libc::c_char,
                );
                if sslprm.log_opts as libc::c_uint
                    & SSL_LogStartup as libc::c_int as libc::c_uint != 0
                {
                    logit(
                        6 as libc::c_int,
                        b"New SSL Cipher List: %s\0" as *const u8 as *const libc::c_char,
                        (sslprm.cipher_list).as_mut_ptr(),
                    );
                }
            }
        } else if sslprm.allowDH == 2 as libc::c_int {
            strncpy(
                (sslprm.cipher_list).as_mut_ptr(),
                b"ADH@SECLEVEL=0\0" as *const u8 as *const libc::c_char,
                (256 as libc::c_int - 1 as libc::c_int) as libc::c_ulong,
            );
        }
        if SSL_CTX_set_cipher_list(ctx, (sslprm.cipher_list).as_mut_ptr())
            == 0 as libc::c_int
        {
            printf(
                b"Error: Could not set SSL/TLS cipher list: %s\n\0" as *const u8
                    as *const libc::c_char,
                (sslprm.cipher_list).as_mut_ptr(),
            );
            loop {
                x = ERR_get_error_line_data(
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                ) as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                printf(
                    b"Could not set SSL/TLS cipher list '%s': %s\n\0" as *const u8
                        as *const libc::c_char,
                    (sslprm.cipher_list).as_mut_ptr(),
                    ERR_reason_error_string(x as libc::c_ulong),
                );
            }
            SSL_CTX_free(ctx);
            exit(timeout_return_code);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn set_sig_handlers() {
    let mut sig_action: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    sig_action.__sigaction_handler.sa_sigaction = None;
    sig_action
        .__sigaction_handler
        .sa_handler = Some(alarm_handler as unsafe extern "C" fn(libc::c_int) -> ());
    sigfillset(&mut sig_action.sa_mask);
    sig_action.sa_flags = 0x40000000 as libc::c_int | 0x10000000 as libc::c_int;
    sigaction(14 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    alarm(socket_timeout as libc::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn connect_to_remote() -> libc::c_int {
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut inaddr: *mut in_addr = 0 as *mut in_addr;
    let mut addrlen: socklen_t = 0;
    let mut result: libc::c_int = 0;
    let mut rc: libc::c_int = 0;
    let mut ssl_err: libc::c_int = 0;
    let mut ern: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut nerrs: libc::c_int = 0 as libc::c_int;
    sd = my_connect(
        server_name,
        &mut hostaddr,
        server_port,
        address_family,
        bind_address,
        stderr_to_stdout,
    );
    if sd < 0 as libc::c_int {
        exit(timeout_return_code);
    }
    result = 0 as libc::c_int;
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    rc = getpeername(
        sd,
        &mut addr as *mut sockaddr_storage as *mut sockaddr,
        &mut addrlen,
    );
    if addr.ss_family as libc::c_int == 2 as libc::c_int {
        let mut addrin: *mut sockaddr_in = &mut addr as *mut sockaddr_storage
            as *mut sockaddr_in;
        inaddr = &mut (*addrin).sin_addr;
    } else {
        let mut addrin_0: *mut sockaddr_in6 = &mut addr as *mut sockaddr_storage
            as *mut sockaddr_in6;
        inaddr = &mut (*addrin_0).sin6_addr as *mut in6_addr as *mut in_addr;
    }
    if (inet_ntop(
        addr.ss_family as libc::c_int,
        inaddr as *const libc::c_void,
        rem_host.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong as socklen_t,
    ))
        .is_null()
    {
        strncpy(
            rem_host.as_mut_ptr(),
            b"Unknown\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
        );
    }
    rem_host[(256 as libc::c_int - 1 as libc::c_int)
        as usize] = '\0' as i32 as libc::c_char;
    if sslprm.log_opts as libc::c_uint & SSL_LogIpAddr as libc::c_int as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        logit(
            7 as libc::c_int,
            b"Connected to %s\0" as *const u8 as *const libc::c_char,
            rem_host.as_mut_ptr(),
        );
    }
    if use_ssl == 0 as libc::c_int {
        return result;
    }
    ssl = SSL_new(ctx);
    if ssl.is_null() {
        printf(
            b"CHECK_NRPE: Error - Could not create SSL connection structure.\n\0"
                as *const u8 as *const libc::c_char,
        );
        return timeout_return_code;
    }
    SSL_set_fd(ssl, sd);
    rc = SSL_connect(ssl);
    if rc != 1 as libc::c_int {
        ern = *__errno_location();
        ssl_err = SSL_get_error(ssl, rc);
        if sslprm.log_opts as libc::c_uint
            & (SSL_LogCertDetails as libc::c_int | SSL_LogIfClientCert as libc::c_int)
                as libc::c_uint != 0
        {
            rc = 0 as libc::c_int;
            loop {
                x = ERR_get_error_line_data(
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                ) as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                logit(
                    3 as libc::c_int,
                    b"Error: (ERR_get_error_line_data = %d), Could not complete SSL handshake with %s: %s\0"
                        as *const u8 as *const libc::c_char,
                    x,
                    rem_host.as_mut_ptr(),
                    ERR_reason_error_string(x as libc::c_ulong),
                );
                nerrs += 1;
            }
            if nerrs == 0 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Error: (nerrs = 0) Could not complete SSL handshake with %s: rc=%d SSL-error=%d\0"
                        as *const u8 as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                    rc,
                    ssl_err,
                );
            }
        } else {
            loop {
                x = ERR_get_error_line_data(
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                    0 as *mut *const libc::c_char,
                    0 as *mut libc::c_int,
                ) as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                logit(
                    3 as libc::c_int,
                    b"Error: (!log_opts) Could not complete SSL handshake with %s: %s\0"
                        as *const u8 as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                    ERR_reason_error_string(x as libc::c_ulong),
                );
                nerrs += 1;
            }
            if nerrs == 0 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Error: (nerrs = 0)(!log_opts) Could not complete SSL handshake with %s: rc=%d SSL-error=%d\0"
                        as *const u8 as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                    rc,
                    ssl_err,
                );
            }
        }
        if ssl_err == 5 as libc::c_int {
            if ern == 0 as libc::c_int {
                printf(
                    b"CHECK_NRPE: Error - Could not connect to %s. Check system logs on %s\n\0"
                        as *const u8 as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                    rem_host.as_mut_ptr(),
                );
            } else {
                printf(
                    b"CHECK_NRPE: Error - Could not connect to %s: %s\n\0" as *const u8
                        as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                    strerror(ern),
                );
            }
        } else {
            printf(
                b"CHECK_NRPE: (ssl_err != 5) Error - Could not complete SSL handshake with %s: %d\n\0"
                    as *const u8 as *const libc::c_char,
                rem_host.as_mut_ptr(),
                ssl_err,
            );
        }
        result = timeout_return_code;
    } else {
        if sslprm.log_opts as libc::c_uint
            & SSL_LogVersion as libc::c_int as libc::c_uint != 0
        {
            logit(
                5 as libc::c_int,
                b"Remote %s - SSL Version: %s\0" as *const u8 as *const libc::c_char,
                rem_host.as_mut_ptr(),
                SSL_get_version(ssl),
            );
        }
        if sslprm.log_opts as libc::c_uint & SSL_LogCipher as libc::c_int as libc::c_uint
            != 0
        {
            let mut c: *const SSL_CIPHER = SSL_get_current_cipher(ssl);
            logit(
                5 as libc::c_int,
                b"Remote %s - %s, Cipher is %s\0" as *const u8 as *const libc::c_char,
                rem_host.as_mut_ptr(),
                SSL_CIPHER_get_version(c),
                SSL_CIPHER_get_name(c),
            );
        }
        if sslprm.log_opts as libc::c_uint
            & SSL_LogIfClientCert as libc::c_int as libc::c_uint != 0
            || sslprm.log_opts as libc::c_uint
                & SSL_LogCertDetails as libc::c_int as libc::c_uint != 0
        {
            let mut peer_cn: [libc::c_char; 256] = [0; 256];
            let mut buffer: [libc::c_char; 2048] = [0; 2048];
            let mut peer: *mut X509 = SSL_get_peer_certificate(ssl);
            if !peer.is_null() {
                if sslprm.log_opts as libc::c_uint
                    & SSL_LogIfClientCert as libc::c_int as libc::c_uint != 0
                {
                    logit(
                        5 as libc::c_int,
                        b"SSL %s has %s certificate\0" as *const u8
                            as *const libc::c_char,
                        rem_host.as_mut_ptr(),
                        if SSL_get_verify_result(ssl) == 0 as libc::c_int as libc::c_long
                        {
                            b"a valid\0" as *const u8 as *const libc::c_char
                        } else {
                            b"an invalid\0" as *const u8 as *const libc::c_char
                        },
                    );
                }
                if sslprm.log_opts as libc::c_uint
                    & SSL_LogCertDetails as libc::c_int as libc::c_uint != 0
                {
                    X509_NAME_oneline(
                        X509_get_subject_name(peer),
                        buffer.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong
                            as libc::c_int,
                    );
                    logit(
                        5 as libc::c_int,
                        b"SSL %s Cert Name: %s\0" as *const u8 as *const libc::c_char,
                        rem_host.as_mut_ptr(),
                        buffer.as_mut_ptr(),
                    );
                    X509_NAME_oneline(
                        X509_get_issuer_name(peer),
                        buffer.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong
                            as libc::c_int,
                    );
                    logit(
                        5 as libc::c_int,
                        b"SSL %s Cert Issuer: %s\0" as *const u8 as *const libc::c_char,
                        rem_host.as_mut_ptr(),
                        buffer.as_mut_ptr(),
                    );
                }
            } else {
                logit(
                    5 as libc::c_int,
                    b"SSL Did not get certificate from %s\0" as *const u8
                        as *const libc::c_char,
                    rem_host.as_mut_ptr(),
                );
            }
        }
    }
    if result != 0 as libc::c_int {
        SSL_CTX_free(ctx);
        close(sd);
        exit(result);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn send_request() -> libc::c_int {
    let mut v2_send_packet: *mut v2_packet = 0 as *mut v2_packet;
    let mut v3_send_packet: *mut v3_packet = 0 as *mut v3_packet;
    let mut calculated_crc32: u_int32_t = 0;
    let mut rc: libc::c_int = 0;
    let mut bytes_to_send: libc::c_int = 0;
    let mut pkt_size: libc::c_int = 0;
    let mut send_pkt: *mut libc::c_char = 0 as *mut libc::c_char;
    if packet_ver == 2 as libc::c_int {
        pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong as libc::c_int;
        if payload_size > 0 as libc::c_int {
            pkt_size = (::core::mem::size_of::<v2_packet>() as libc::c_ulong)
                .wrapping_sub(1024 as libc::c_int as libc::c_ulong)
                .wrapping_add(payload_size as libc::c_ulong) as libc::c_int;
        }
        v2_send_packet = calloc(
            1 as libc::c_int as libc::c_ulong,
            pkt_size as libc::c_ulong,
        ) as *mut v2_packet;
        send_pkt = v2_send_packet as *mut libc::c_char;
        randomize_buffer(v2_send_packet as *mut libc::c_char, pkt_size);
        (*v2_send_packet)
            .packet_version = __bswap_16(packet_ver as __uint16_t) as int16_t;
        (*v2_send_packet)
            .packet_type = __bswap_16(1 as libc::c_int as __uint16_t) as int16_t;
        if payload_size > 0 as libc::c_int {
            strncpy(
                &mut *((*v2_send_packet).buffer)
                    .as_mut_ptr()
                    .offset(0 as libc::c_int as isize),
                query.as_mut_ptr(),
                payload_size as libc::c_ulong,
            );
            (*v2_send_packet)
                .buffer[(payload_size - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        } else {
            strncpy(
                &mut *((*v2_send_packet).buffer)
                    .as_mut_ptr()
                    .offset(0 as libc::c_int as isize),
                query.as_mut_ptr(),
                1024 as libc::c_int as libc::c_ulong,
            );
            (*v2_send_packet)
                .buffer[(1024 as libc::c_int - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        }
        (*v2_send_packet).crc32_value = 0 as libc::c_int as u_int32_t;
        calculated_crc32 = calculate_crc32(send_pkt, pkt_size) as u_int32_t;
        (*v2_send_packet).crc32_value = __bswap_32(calculated_crc32);
    } else {
        pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
            .wrapping_sub(4 as libc::c_int as libc::c_ulong)
            .wrapping_add(strlen(query.as_mut_ptr()))
            .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int;
        if packet_ver == 3 as libc::c_int {
            pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_add(strlen(query.as_mut_ptr()))
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int;
        }
        if (pkt_size as libc::c_ulong)
            < ::core::mem::size_of::<v2_packet>() as libc::c_ulong
        {
            pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong
                as libc::c_int;
        }
        v3_send_packet = calloc(
            1 as libc::c_int as libc::c_ulong,
            pkt_size as libc::c_ulong,
        ) as *mut v3_packet;
        send_pkt = v3_send_packet as *mut libc::c_char;
        (*v3_send_packet)
            .packet_version = __bswap_16(packet_ver as __uint16_t) as int16_t;
        (*v3_send_packet)
            .packet_type = __bswap_16(1 as libc::c_int as __uint16_t) as int16_t;
        (*v3_send_packet).alignment = 0 as libc::c_int as int16_t;
        (*v3_send_packet)
            .buffer_length = (pkt_size as libc::c_ulong)
            .wrapping_sub(::core::mem::size_of::<v3_packet>() as libc::c_ulong)
            as int32_t;
        (*v3_send_packet).buffer_length
            += if packet_ver == 4 as libc::c_int {
                4 as libc::c_int
            } else {
                1 as libc::c_int
            };
        (*v3_send_packet)
            .buffer_length = __bswap_32((*v3_send_packet).buffer_length as __uint32_t)
            as int32_t;
        strcpy(
            &mut *((*v3_send_packet).buffer)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize),
            query.as_mut_ptr(),
        );
        (*v3_send_packet).crc32_value = 0 as libc::c_int as u_int32_t;
        calculated_crc32 = calculate_crc32(v3_send_packet as *mut libc::c_char, pkt_size)
            as u_int32_t;
        (*v3_send_packet).crc32_value = __bswap_32(calculated_crc32);
    }
    bytes_to_send = pkt_size;
    if use_ssl == 0 as libc::c_int {
        rc = sendall(sd, send_pkt, &mut bytes_to_send);
    } else {
        rc = SSL_write(ssl, send_pkt as *const libc::c_void, bytes_to_send);
        if rc < 0 as libc::c_int {
            rc = -(1 as libc::c_int);
        }
    }
    if !v3_send_packet.is_null() {
        free(v3_send_packet as *mut libc::c_void);
    }
    if !v2_send_packet.is_null() {
        free(v2_send_packet as *mut libc::c_void);
    }
    if rc == -(1 as libc::c_int) {
        printf(
            b"CHECK_NRPE: Error sending query to host.\n\0" as *const u8
                as *const libc::c_char,
        );
        close(sd);
        return 3 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn read_packet(
    mut sock: libc::c_int,
    mut ssl_ptr: *mut libc::c_void,
    mut v2_pkt: *mut *mut v2_packet,
    mut v3_pkt: *mut *mut v3_packet,
) -> libc::c_int {
    let mut packet: v2_packet = v2_packet {
        packet_version: 0,
        packet_type: 0,
        crc32_value: 0,
        result_code: 0,
        buffer: [0; 1024],
    };
    let mut pkt_size: int32_t = 0;
    let mut common_size: int32_t = 0;
    let mut tot_bytes: int32_t = 0;
    let mut bytes_to_recv: int32_t = 0;
    let mut buffer_size: int32_t = 0;
    let mut bytes_read: int32_t = 0 as libc::c_int;
    let mut rc: libc::c_int = 0;
    let mut buff_ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    bytes_to_recv = (packet.buffer)
        .as_mut_ptr()
        .offset_from(&mut packet as *mut v2_packet as *mut libc::c_char) as libc::c_long
        as int32_t;
    tot_bytes = bytes_to_recv;
    common_size = tot_bytes;
    if use_ssl == 0 as libc::c_int {
        rc = recvall(
            sock,
            &mut packet as *mut v2_packet as *mut libc::c_char,
            &mut tot_bytes,
            socket_timeout,
        );
        if rc <= 0 as libc::c_int || rc != bytes_to_recv {
            if rc < bytes_to_recv {
                if packet_ver <= 3 as libc::c_int {
                    printf(
                        b"CHECK_NRPE: Receive header underflow - only %d bytes received (%zu expected).\n\0"
                            as *const u8 as *const libc::c_char,
                        rc,
                        ::core::mem::size_of::<int32_t>() as libc::c_ulong,
                    );
                }
            }
            return -(1 as libc::c_int);
        }
        if packet_ver != __bswap_16(packet.packet_version as __uint16_t) as libc::c_int {
            printf(
                b"CHECK_NRPE: Invalid packet version received from server.\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if __bswap_16(packet.packet_type as __uint16_t) as libc::c_int
            != 2 as libc::c_int
        {
            printf(
                b"CHECK_NRPE: Invalid packet type received from server.\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if packet_ver == 2 as libc::c_int {
            pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong as int32_t;
            if payload_size > 0 as libc::c_int {
                pkt_size = common_size + payload_size;
                buffer_size = payload_size;
            } else {
                buffer_size = pkt_size - common_size;
            }
            *v2_pkt = calloc(
                1 as libc::c_int as libc::c_ulong,
                pkt_size as libc::c_ulong,
            ) as *mut v2_packet;
            if (*v2_pkt).is_null() {
                logit(
                    3 as libc::c_int,
                    b"Error: Could not allocate memory for packet\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v2_pkt as *mut libc::c_void,
                &mut packet as *mut v2_packet as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            buff_ptr = ((**v2_pkt).buffer).as_mut_ptr();
            memset(
                buff_ptr as *mut libc::c_void,
                0 as libc::c_int,
                buffer_size as libc::c_ulong,
            );
        } else {
            pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as int32_t;
            bytes_to_recv = ::core::mem::size_of::<int16_t>() as libc::c_ulong
                as int32_t;
            rc = recvall(
                sock,
                &mut buffer_size as *mut int32_t as *mut libc::c_char,
                &mut bytes_to_recv,
                socket_timeout,
            );
            if rc <= 0 as libc::c_int
                || bytes_to_recv as libc::c_ulong
                    != ::core::mem::size_of::<int16_t>() as libc::c_ulong
            {
                return -(1 as libc::c_int);
            }
            tot_bytes += rc;
            bytes_to_recv = ::core::mem::size_of::<int32_t>() as libc::c_ulong
                as int32_t;
            rc = recvall(
                sock,
                &mut buffer_size as *mut int32_t as *mut libc::c_char,
                &mut bytes_to_recv,
                socket_timeout,
            );
            if rc <= 0 as libc::c_int
                || bytes_to_recv as libc::c_ulong
                    != ::core::mem::size_of::<int32_t>() as libc::c_ulong
            {
                return -(1 as libc::c_int);
            }
            tot_bytes += rc;
            buffer_size = __bswap_32(buffer_size as __uint32_t) as int32_t;
            if buffer_size < 0 as libc::c_int || buffer_size > 65536 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Error: Received packet with invalid buffer size\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            pkt_size += buffer_size;
            *v3_pkt = calloc(
                1 as libc::c_int as libc::c_ulong,
                pkt_size as libc::c_ulong,
            ) as *mut v3_packet;
            if (*v3_pkt).is_null() {
                logit(
                    3 as libc::c_int,
                    b"Error: Could not allocate memory for packet\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v3_pkt as *mut libc::c_void,
                &mut packet as *mut v2_packet as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            (**v3_pkt).buffer_length = __bswap_32(buffer_size as __uint32_t) as int32_t;
            buff_ptr = ((**v3_pkt).buffer).as_mut_ptr();
        }
        bytes_to_recv = buffer_size;
        rc = recvall(sock, buff_ptr, &mut bytes_to_recv, socket_timeout);
        if rc <= 0 as libc::c_int || rc != buffer_size {
            if packet_ver >= 3 as libc::c_int {
                free(*v3_pkt as *mut libc::c_void);
                *v3_pkt = 0 as *mut v3_packet;
            } else {
                free(*v2_pkt as *mut libc::c_void);
                *v2_pkt = 0 as *mut v2_packet;
            }
            if rc < buffer_size {
                printf(
                    b"CHECK_NRPE: Receive underflow - only %d bytes received (%zu expected).\n\0"
                        as *const u8 as *const libc::c_char,
                    rc,
                    ::core::mem::size_of::<int32_t>() as libc::c_ulong,
                );
            }
            return -(1 as libc::c_int);
        } else {
            tot_bytes += rc;
        }
    } else {
        let mut ssl_0: *mut SSL = ssl_ptr as *mut SSL;
        loop {
            rc = SSL_read(
                ssl_0,
                &mut packet as *mut v2_packet as *mut libc::c_void,
                bytes_to_recv,
            );
            if !(rc <= 0 as libc::c_int && SSL_get_error(ssl_0, rc) == 2 as libc::c_int)
            {
                break;
            }
        }
        if rc <= 0 as libc::c_int || rc != bytes_to_recv {
            if rc < bytes_to_recv {
                if packet_ver < 3 as libc::c_int || packet_ver > 4 as libc::c_int {
                    printf(
                        b"CHECK_NRPE: Receive header underflow - only %d bytes received (%zu expected).\n\0"
                            as *const u8 as *const libc::c_char,
                        rc,
                        ::core::mem::size_of::<int32_t>() as libc::c_ulong,
                    );
                }
            }
            return -(1 as libc::c_int);
        }
        if packet_ver != __bswap_16(packet.packet_version as __uint16_t) as libc::c_int {
            printf(
                b"CHECK_NRPE: Invalid packet version received from server.\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if __bswap_16(packet.packet_type as __uint16_t) as libc::c_int
            != 2 as libc::c_int
        {
            printf(
                b"CHECK_NRPE: Invalid packet type received from server.\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if packet_ver == 2 as libc::c_int {
            pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong as int32_t;
            if payload_size > 0 as libc::c_int {
                pkt_size = common_size + payload_size;
                buffer_size = payload_size;
            } else {
                buffer_size = pkt_size - common_size;
            }
            *v2_pkt = calloc(
                1 as libc::c_int as libc::c_ulong,
                pkt_size as libc::c_ulong,
            ) as *mut v2_packet;
            if (*v2_pkt).is_null() {
                logit(
                    3 as libc::c_int,
                    b"Error: Could not allocate memory for packet\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v2_pkt as *mut libc::c_void,
                &mut packet as *mut v2_packet as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            buff_ptr = ((**v2_pkt).buffer).as_mut_ptr();
            memset(
                buff_ptr as *mut libc::c_void,
                0 as libc::c_int,
                buffer_size as libc::c_ulong,
            );
        } else {
            pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as int32_t;
            bytes_to_recv = ::core::mem::size_of::<int16_t>() as libc::c_ulong
                as int32_t;
            loop {
                rc = SSL_read(
                    ssl_0,
                    &mut buffer_size as *mut int32_t as *mut libc::c_void,
                    bytes_to_recv,
                );
                if !(rc <= 0 as libc::c_int
                    && SSL_get_error(ssl_0, rc) == 2 as libc::c_int)
                {
                    break;
                }
            }
            if rc <= 0 as libc::c_int
                || bytes_to_recv as libc::c_ulong
                    != ::core::mem::size_of::<int16_t>() as libc::c_ulong
            {
                return -(1 as libc::c_int);
            }
            tot_bytes += rc;
            bytes_to_recv = ::core::mem::size_of::<int32_t>() as libc::c_ulong
                as int32_t;
            loop {
                rc = SSL_read(
                    ssl_0,
                    &mut buffer_size as *mut int32_t as *mut libc::c_void,
                    bytes_to_recv,
                );
                if !(rc <= 0 as libc::c_int
                    && SSL_get_error(ssl_0, rc) == 2 as libc::c_int)
                {
                    break;
                }
            }
            if rc <= 0 as libc::c_int
                || bytes_to_recv as libc::c_ulong
                    != ::core::mem::size_of::<int32_t>() as libc::c_ulong
            {
                return -(1 as libc::c_int);
            }
            tot_bytes += rc;
            buffer_size = __bswap_32(buffer_size as __uint32_t) as int32_t;
            if buffer_size < 0 as libc::c_int || buffer_size > 65536 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Error: Received packet with invalid buffer size\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            pkt_size += buffer_size;
            *v3_pkt = calloc(
                1 as libc::c_int as libc::c_ulong,
                pkt_size as libc::c_ulong,
            ) as *mut v3_packet;
            if (*v3_pkt).is_null() {
                logit(
                    3 as libc::c_int,
                    b"Error: Could not allocate memory for packet\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v3_pkt as *mut libc::c_void,
                &mut packet as *mut v2_packet as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            (**v3_pkt).buffer_length = __bswap_32(buffer_size as __uint32_t) as int32_t;
            buff_ptr = ((**v3_pkt).buffer).as_mut_ptr();
        }
        bytes_to_recv = buffer_size;
        loop {
            loop {
                rc = SSL_read(
                    ssl_0,
                    &mut *buff_ptr.offset(bytes_read as isize) as *mut libc::c_char
                        as *mut libc::c_void,
                    bytes_to_recv,
                );
                if !(rc <= 0 as libc::c_int
                    && SSL_get_error(ssl_0, rc) == 2 as libc::c_int)
                {
                    break;
                }
            }
            if rc <= 0 as libc::c_int {
                break;
            }
            bytes_read += rc;
            bytes_to_recv -= rc;
            tot_bytes += rc;
        }
        if rc < 0 as libc::c_int || bytes_read != buffer_size {
            if packet_ver >= 3 as libc::c_int {
                free(*v3_pkt as *mut libc::c_void);
                *v3_pkt = 0 as *mut v3_packet;
            } else {
                free(*v2_pkt as *mut libc::c_void);
                *v2_pkt = 0 as *mut v2_packet;
            }
            if bytes_read != buffer_size {
                if packet_ver >= 3 as libc::c_int {
                    printf(
                        b"CHECK_NRPE: Receive buffer size - %ld bytes received (%zu expected).\n\0"
                            as *const u8 as *const libc::c_char,
                        bytes_read as libc::c_long,
                        ::core::mem::size_of::<int32_t>() as libc::c_ulong,
                    );
                } else {
                    printf(
                        b"CHECK_NRPE: Receive underflow - only %ld bytes received (%zu expected).\n\0"
                            as *const u8 as *const libc::c_char,
                        bytes_read as libc::c_long,
                        ::core::mem::size_of::<int32_t>() as libc::c_ulong,
                    );
                }
            }
            return -(1 as libc::c_int);
        }
    }
    return tot_bytes;
}
#[no_mangle]
pub unsafe extern "C" fn read_response() -> libc::c_int {
    let mut v2_receive_packet: *mut v2_packet = 0 as *mut v2_packet;
    let mut v3_receive_packet: *mut v3_packet = 0 as *mut v3_packet;
    let mut packet_crc32: u_int32_t = 0;
    let mut calculated_crc32: u_int32_t = 0;
    let mut pkt_size: int32_t = 0;
    let mut buffer_size: int32_t = 0;
    let mut rc: libc::c_int = 0;
    let mut result: libc::c_int = 0;
    alarm(0 as libc::c_int as libc::c_uint);
    set_sig_handlers();
    rc = read_packet(
        sd,
        ssl as *mut libc::c_void,
        &mut v2_receive_packet,
        &mut v3_receive_packet,
    );
    alarm(0 as libc::c_int as libc::c_uint);
    if use_ssl == 1 as libc::c_int {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
    graceful_close(sd, 1000 as libc::c_int);
    if rc < 0 as libc::c_int {
        if !v2_receive_packet.is_null() {
            free(v2_receive_packet as *mut libc::c_void);
        }
        if !v3_receive_packet.is_null() {
            free(v3_receive_packet as *mut libc::c_void);
        }
        if packet_ver >= 3 as libc::c_int {
            return -(1 as libc::c_int);
        }
        return 3 as libc::c_int;
    } else {
        if rc == 0 as libc::c_int {
            printf(
                b"CHECK_NRPE: Received 0 bytes from daemon.  Check the remote server logs for error messages.\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if !v3_receive_packet.is_null() {
                free(v3_receive_packet as *mut libc::c_void);
            }
            if !v2_receive_packet.is_null() {
                free(v2_receive_packet as *mut libc::c_void);
            }
            return 3 as libc::c_int;
        }
    }
    if packet_ver >= 3 as libc::c_int {
        buffer_size = __bswap_32((*v3_receive_packet).buffer_length as __uint32_t)
            as int32_t;
        if buffer_size < 0 as libc::c_int || buffer_size > 65536 as libc::c_int {
            printf(
                b"CHECK_NRPE: Response packet had invalid buffer size.\n\0" as *const u8
                    as *const libc::c_char,
            );
            close(sd);
            if !v3_receive_packet.is_null() {
                free(v3_receive_packet as *mut libc::c_void);
            }
            if !v2_receive_packet.is_null() {
                free(v2_receive_packet as *mut libc::c_void);
            }
            return 3 as libc::c_int;
        }
        pkt_size = ::core::mem::size_of::<v3_packet>() as libc::c_ulong as int32_t;
        pkt_size
            -= if packet_ver == 3 as libc::c_int {
                1 as libc::c_int
            } else {
                4 as libc::c_int
            };
        pkt_size += buffer_size;
        packet_crc32 = __bswap_32((*v3_receive_packet).crc32_value);
        (*v3_receive_packet).crc32_value = 0 as libc::c_long as u_int32_t;
        (*v3_receive_packet).alignment = 0 as libc::c_int as int16_t;
        calculated_crc32 = calculate_crc32(
            v3_receive_packet as *mut libc::c_char,
            pkt_size,
        ) as u_int32_t;
    } else {
        pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong as int32_t;
        if payload_size > 0 as libc::c_int {
            pkt_size = (::core::mem::size_of::<v2_packet>() as libc::c_ulong)
                .wrapping_sub(1024 as libc::c_int as libc::c_ulong)
                .wrapping_add(payload_size as libc::c_ulong) as int32_t;
        }
        packet_crc32 = __bswap_32((*v2_receive_packet).crc32_value);
        (*v2_receive_packet).crc32_value = 0 as libc::c_long as u_int32_t;
        calculated_crc32 = calculate_crc32(
            v2_receive_packet as *mut libc::c_char,
            pkt_size,
        ) as u_int32_t;
    }
    if packet_crc32 != calculated_crc32 {
        printf(
            b"CHECK_NRPE: Response packet had invalid CRC32.\n\0" as *const u8
                as *const libc::c_char,
        );
        close(sd);
        if !v3_receive_packet.is_null() {
            free(v3_receive_packet as *mut libc::c_void);
        }
        if !v2_receive_packet.is_null() {
            free(v2_receive_packet as *mut libc::c_void);
        }
        return 3 as libc::c_int;
    }
    if packet_ver >= 3 as libc::c_int {
        result = __bswap_16((*v3_receive_packet).result_code as __uint16_t)
            as libc::c_int;
        if (*v3_receive_packet).buffer_length == 0 as libc::c_int {
            printf(
                b"CHECK_NRPE: No output returned from daemon.\n\0" as *const u8
                    as *const libc::c_char,
            );
        } else {
            printf(
                b"%s\n\0" as *const u8 as *const libc::c_char,
                ((*v3_receive_packet).buffer).as_mut_ptr(),
            );
        }
    } else {
        result = __bswap_16((*v2_receive_packet).result_code as __uint16_t)
            as libc::c_int;
        if payload_size > 0 as libc::c_int {
            (*v2_receive_packet)
                .buffer[(payload_size - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        } else {
            (*v2_receive_packet)
                .buffer[(1024 as libc::c_int - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        }
        if strcmp(
            ((*v2_receive_packet).buffer).as_mut_ptr(),
            b"\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            printf(
                b"CHECK_NRPE: No output returned from daemon.\n\0" as *const u8
                    as *const libc::c_char,
            );
        } else if !(strstr(
            ((*v2_receive_packet).buffer).as_mut_ptr(),
            b"Invalid packet version.3\0" as *const u8 as *const libc::c_char,
        ))
            .is_null()
        {
            return -(1 as libc::c_int)
        } else {
            printf(
                b"%s\n\0" as *const u8 as *const libc::c_char,
                ((*v2_receive_packet).buffer).as_mut_ptr(),
            );
        }
    }
    if !v3_receive_packet.is_null() {
        free(v3_receive_packet as *mut libc::c_void);
    }
    if !v2_receive_packet.is_null() {
        free(v2_receive_packet as *mut libc::c_void);
    }
    return result;
}
unsafe extern "C" fn verify_callback(
    mut preverify_ok: libc::c_int,
    mut ctx_0: *mut X509_STORE_CTX,
) -> libc::c_int {
    let mut name: [libc::c_char; 256] = [0; 256];
    let mut issuer: [libc::c_char; 256] = [0; 256];
    let mut err_cert: *mut X509 = 0 as *mut X509;
    let mut err: libc::c_int = 0;
    let mut ssl_0: *mut SSL = 0 as *mut SSL;
    if preverify_ok != 0
        || sslprm.log_opts as libc::c_uint
            & SSL_LogCertDetails as libc::c_int as libc::c_uint
            == 0 as libc::c_int as libc::c_uint
    {
        return preverify_ok;
    }
    err_cert = X509_STORE_CTX_get_current_cert(ctx_0);
    err = X509_STORE_CTX_get_error(ctx_0);
    ssl_0 = X509_STORE_CTX_get_ex_data(ctx_0, SSL_get_ex_data_X509_STORE_CTX_idx())
        as *mut SSL;
    X509_NAME_oneline(
        X509_get_subject_name(err_cert),
        name.as_mut_ptr(),
        256 as libc::c_int,
    );
    X509_NAME_oneline(
        X509_get_issuer_name(err_cert),
        issuer.as_mut_ptr(),
        256 as libc::c_int,
    );
    if preverify_ok == 0
        && sslprm.client_certs as libc::c_uint
            >= Ask_For_Cert as libc::c_int as libc::c_uint
        && sslprm.log_opts as libc::c_uint
            & SSL_LogCertDetails as libc::c_int as libc::c_uint != 0
    {
        logit(
            3 as libc::c_int,
            b"SSL Client has an invalid certificate: %s (issuer=%s) err=%d:%s\0"
                as *const u8 as *const libc::c_char,
            name.as_mut_ptr(),
            issuer.as_mut_ptr(),
            err,
            X509_verify_cert_error_string(err as libc::c_long),
        );
    }
    return preverify_ok;
}
#[no_mangle]
pub unsafe extern "C" fn alarm_handler(mut sig: libc::c_int) {
    let msg1: [libc::c_char; 18] = *::core::mem::transmute::<
        &[u8; 18],
        &[libc::c_char; 18],
    >(b"CHECK_NRPE STATE \0");
    let msg2: [libc::c_char; 24] = *::core::mem::transmute::<
        &[u8; 24],
        &[libc::c_char; 24],
    >(b": Socket timeout after \0");
    let msg3: [libc::c_char; 11] = *::core::mem::transmute::<
        &[u8; 11],
        &[libc::c_char; 11],
    >(b" seconds.\n\0");
    let mut text: *const libc::c_char = state_text(timeout_return_code);
    let mut lth1: size_t = 0 as libc::c_int as size_t;
    let mut lth2: size_t = 0 as libc::c_int as size_t;
    lth1 = 0 as libc::c_int as size_t;
    while lth1 < 10 as libc::c_int as libc::c_ulong {
        if *text.offset(lth1 as isize) as libc::c_int == 0 as libc::c_int {
            break;
        }
        lth1 = lth1.wrapping_add(1);
    }
    lth2 = 0 as libc::c_int as size_t;
    while lth2 < 10 as libc::c_int as libc::c_ulong {
        if timeout_txt[lth2 as usize] as libc::c_int == 0 as libc::c_int {
            break;
        }
        lth2 = lth2.wrapping_add(1);
    }
    if write(
        1 as libc::c_int,
        msg1.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) == -(1 as libc::c_int) as libc::c_long
        || write(1 as libc::c_int, text as *const libc::c_void, lth1)
            == -(1 as libc::c_int) as libc::c_long
        || write(
            1 as libc::c_int,
            msg2.as_ptr() as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) == -(1 as libc::c_int) as libc::c_long
        || write(1 as libc::c_int, timeout_txt.as_mut_ptr() as *const libc::c_void, lth2)
            == -(1 as libc::c_int) as libc::c_long
        || write(
            1 as libc::c_int,
            msg3.as_ptr() as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 11]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) == -(1 as libc::c_int) as libc::c_long
    {
        logit(
            3 as libc::c_int,
            b"ERROR: alarm_handler() write(): %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    exit(timeout_return_code);
}
#[no_mangle]
pub unsafe extern "C" fn graceful_close(
    mut sd_0: libc::c_int,
    mut timeout: libc::c_int,
) -> libc::c_int {
    let mut in_0: fd_set = fd_set { __fds_bits: [0; 16] };
    let mut tv: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    let mut buf: [libc::c_char; 1000] = [0; 1000];
    shutdown(sd_0, SHUT_WR as libc::c_int);
    loop {
        let mut __d0: libc::c_int = 0;
        let mut __d1: libc::c_int = 0;
        let fresh8 = &mut __d0;
        let fresh9;
        let fresh10 = (::core::mem::size_of::<fd_set>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<__fd_mask>() as libc::c_ulong);
        let fresh11 = &mut __d1;
        let fresh12;
        let fresh13 = &mut *(in_0.__fds_bits)
            .as_mut_ptr()
            .offset(0 as libc::c_int as isize) as *mut __fd_mask;
        asm!(
            "cld; rep; stosq", inlateout("cx") c2rust_asm_casts::AsmCast::cast_in(fresh8,
            fresh10) => fresh9, inlateout("di")
            c2rust_asm_casts::AsmCast::cast_in(fresh11, fresh13) => fresh12,
            inlateout("ax") 0 as libc::c_int => _, options(preserves_flags, att_syntax)
        );
        c2rust_asm_casts::AsmCast::cast_out(fresh8, fresh10, fresh9);
        c2rust_asm_casts::AsmCast::cast_out(fresh11, fresh13, fresh12);
        in_0
            .__fds_bits[(sd_0
            / (8 as libc::c_int
                * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong as libc::c_int))
            as usize]
            |= ((1 as libc::c_ulong)
                << sd_0
                    % (8 as libc::c_int
                        * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                            as libc::c_int)) as __fd_mask;
        tv.tv_sec = (timeout / 1000 as libc::c_int) as __time_t;
        tv
            .tv_usec = (timeout % 1000 as libc::c_int * 1000 as libc::c_int)
            as __suseconds_t;
        if 1 as libc::c_int
            != select(
                sd_0 + 1 as libc::c_int,
                &mut in_0,
                0 as *mut fd_set,
                0 as *mut fd_set,
                &mut tv,
            )
        {
            break;
        }
        if 0 as libc::c_int as libc::c_long
            >= recv(
                sd_0,
                buf.as_mut_ptr() as *mut libc::c_void,
                ::core::mem::size_of::<[libc::c_char; 1000]>() as libc::c_ulong,
                0 as libc::c_int,
            )
        {
            break;
        }
    }
    close(sd_0);
    return 0 as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
