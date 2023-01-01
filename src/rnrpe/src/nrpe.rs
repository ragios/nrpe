#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
//#![feature(asm, extern_types)]
#![feature(extern_types)]
use c2rust_asm_casts::AsmCastTrait;
use core::arch::asm;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type bignum_st;
    pub type dh_st;
    pub type x509_st;
    pub type X509_name_st;
    pub type x509_store_ctx_st;
    pub type ossl_init_settings_st;
    pub type engine_st;
    pub type ssl_st;
    pub type ssl_ctx_st;
    pub type ssl_method_st;
    pub type ssl_cipher_st;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn sprintf(_: *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn popen(__command: *const libc::c_char, __modes: *const libc::c_char) -> *mut FILE;
    fn pclose(__stream: *mut FILE) -> libc::c_int;
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
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn putenv(__string: *mut libc::c_char) -> libc::c_int;
    static mut optarg: *mut libc::c_char;
    fn getopt_long(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
        __longopts: *const option,
        __longind: *mut libc::c_int,
    ) -> libc::c_int;
    fn memcpy(
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
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strstr(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn alarm(__seconds: libc::c_uint) -> libc::c_uint;
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;
    fn getcwd(__buf: *mut libc::c_char, __size: size_t) -> *mut libc::c_char;
    fn getpid() -> __pid_t;
    fn setpgid(__pid: __pid_t, __pgid: __pid_t) -> libc::c_int;
    fn setsid() -> __pid_t;
    fn geteuid() -> __uid_t;
    fn getegid() -> __gid_t;
    fn setuid(__uid: __uid_t) -> libc::c_int;
    fn seteuid(__uid: __uid_t) -> libc::c_int;
    fn setgid(__gid: __gid_t) -> libc::c_int;
    fn fork() -> __pid_t;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn signal(__sig: libc::c_int, __handler: __sighandler_t) -> __sighandler_t;
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    fn sigfillset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;
    fn closelog();
    fn openlog(
        __ident: *const libc::c_char,
        __option: libc::c_int,
        __facility: libc::c_int,
    );
    fn __xstat(
        __ver: libc::c_int,
        __filename: *const libc::c_char,
        __stat_buf: *mut stat,
    ) -> libc::c_int;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn waitpid(
        __pid: __pid_t,
        __stat_loc: *mut libc::c_int,
        __options: libc::c_int,
    ) -> __pid_t;
    fn __errno_location() -> *mut libc::c_int;
    fn time(__timer: *mut time_t) -> time_t;
    fn socket(
        __domain: libc::c_int,
        __type: libc::c_int,
        __protocol: libc::c_int,
    ) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
    fn getpeername(
        __fd: libc::c_int,
        __addr: *mut sockaddr,
        __len: *mut socklen_t,
    ) -> libc::c_int;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    fn accept(
        __fd: libc::c_int,
        __addr: *mut sockaddr,
        __addr_len: *mut socklen_t,
    ) -> libc::c_int;
    fn inet_ntoa(__in: in_addr) -> *mut libc::c_char;
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn endpwent();
    fn getpwnam(__name: *const libc::c_char) -> *mut passwd;
    fn endgrent();
    fn getgrnam(__name: *const libc::c_char) -> *mut group;
    fn initgroups(__user: *const libc::c_char, __group: __gid_t) -> libc::c_int;
    fn scandir(
        __dir: *const libc::c_char,
        __namelist: *mut *mut *mut dirent,
        __selector: Option::<unsafe extern "C" fn(*const dirent) -> libc::c_int>,
        __cmp: Option::<
            unsafe extern "C" fn(*mut *const dirent, *mut *const dirent) -> libc::c_int,
        >,
    ) -> libc::c_int;
    fn alphasort(__e1: *mut *const dirent, __e2: *mut *const dirent) -> libc::c_int;
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
    fn BN_bin2bn(
        s: *const libc::c_uchar,
        len: libc::c_int,
        ret: *mut BIGNUM,
    ) -> *mut BIGNUM;
    fn BN_free(a: *mut BIGNUM);
    fn DH_new() -> *mut DH;
    fn DH_free(dh: *mut DH);
    fn DH_set0_pqg(
        dh: *mut DH,
        p: *mut BIGNUM,
        q: *mut BIGNUM,
        g: *mut BIGNUM,
    ) -> libc::c_int;
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
    fn SSL_get_fd(s: *const SSL) -> libc::c_int;
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
    fn SSL_CTX_check_private_key(ctx_0: *const SSL_CTX) -> libc::c_int;
    fn SSL_new(ctx_0: *mut SSL_CTX) -> *mut SSL;
    fn SSL_free(ssl: *mut SSL);
    fn SSL_accept(ssl: *mut SSL) -> libc::c_int;
    fn SSL_read(ssl: *mut SSL, buf: *mut libc::c_void, num: libc::c_int) -> libc::c_int;
    fn SSL_write(
        ssl: *mut SSL,
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
    fn TLS_server_method() -> *const SSL_METHOD;
    fn SSL_shutdown(s: *mut SSL) -> libc::c_int;
    fn SSL_CTX_load_verify_locations(
        ctx_0: *mut SSL_CTX,
        CAfile: *const libc::c_char,
        CApath: *const libc::c_char,
    ) -> libc::c_int;
    fn SSL_get_verify_result(ssl: *const SSL) -> libc::c_long;
    fn SSL_get_ex_data_X509_STORE_CTX_idx() -> libc::c_int;
    fn OPENSSL_init_ssl(
        opts: uint64_t,
        settings: *const OPENSSL_INIT_SETTINGS,
    ) -> libc::c_int;
    fn ERR_get_error() -> libc::c_ulong;
    fn ERR_get_error_line_data(
        file: *mut *const libc::c_char,
        line: *mut libc::c_int,
        data: *mut *const libc::c_char,
        flags: *mut libc::c_int,
    ) -> libc::c_ulong;
    fn ERR_error_string(e: libc::c_ulong, buf: *mut libc::c_char) -> *mut libc::c_char;
    fn ERR_reason_error_string(e: libc::c_ulong) -> *const libc::c_char;
    fn RAND_set_rand_engine(engine: *mut ENGINE) -> libc::c_int;
    fn RAND_seed(buf: *const libc::c_void, num: libc::c_int);
    fn RAND_load_file(file: *const libc::c_char, max_bytes: libc::c_long) -> libc::c_int;
    fn RAND_write_file(file: *const libc::c_char) -> libc::c_int;
    fn RAND_file_name(file: *mut libc::c_char, num: size_t) -> *const libc::c_char;
    fn RAND_status() -> libc::c_int;
    fn ENGINE_load_builtin_engines();
    fn ENGINE_register_all_complete() -> libc::c_int;
    fn X509_STORE_CTX_get_current_cert(ctx_0: *mut X509_STORE_CTX) -> *mut X509;
    fn X509_STORE_CTX_get_error(ctx_0: *mut X509_STORE_CTX) -> libc::c_int;
    fn X509_STORE_CTX_get_ex_data(
        ctx_0: *mut X509_STORE_CTX,
        idx: libc::c_int,
    ) -> *mut libc::c_void;
    fn generate_crc32_table();
    fn calculate_crc32(_: *mut libc::c_char, _: libc::c_int) -> libc::c_ulong;
    fn randomize_buffer(_: *mut libc::c_char, _: libc::c_int);
    fn add_listen_addr(
        _: *mut *mut addrinfo,
        _: libc::c_int,
        _: *mut libc::c_char,
        _: libc::c_int,
    );
    fn clean_environ(
        keep_env_vars_0: *const libc::c_char,
        nrpe_user_0: *const libc::c_char,
    ) -> libc::c_int;
    fn sendall(_: libc::c_int, _: *mut libc::c_char, _: *mut libc::c_int) -> libc::c_int;
    fn recvall(
        _: libc::c_int,
        _: *mut libc::c_char,
        _: *mut libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn my_strsep(_: *mut *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn open_log_file();
    fn logit(priority: libc::c_int, format: *const libc::c_char, _: ...);
    fn close_log_file();
    fn display_license();
    fn parse_allowed_hosts(allowed_hosts_0: *mut libc::c_char);
    fn is_an_allowed_host(_: libc::c_int, _: *mut libc::c_void) -> libc::c_int;
    fn show_acl_lists();
    fn asprintf(
        ptr: *mut *mut libc::c_char,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    static mut log_file: *mut libc::c_char;
}
pub type size_t = libc::c_ulong;
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
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
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
pub type fd_mask = __fd_mask;
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
pub type C2RustUnnamed_10 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_10 = 263;
pub const IPPROTO_MPTCP: C2RustUnnamed_10 = 262;
pub const IPPROTO_RAW: C2RustUnnamed_10 = 255;
pub const IPPROTO_ETHERNET: C2RustUnnamed_10 = 143;
pub const IPPROTO_MPLS: C2RustUnnamed_10 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_10 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_10 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_10 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_10 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_10 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_10 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_10 = 92;
pub const IPPROTO_AH: C2RustUnnamed_10 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_10 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_10 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_10 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_10 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_10 = 33;
pub const IPPROTO_TP: C2RustUnnamed_10 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_10 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_10 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_10 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_10 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_10 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_10 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_10 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_10 = 1;
pub const IPPROTO_IP: C2RustUnnamed_10 = 0;
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
pub type C2RustUnnamed_12 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_12 = 8;
pub const _ISpunct: C2RustUnnamed_12 = 4;
pub const _IScntrl: C2RustUnnamed_12 = 2;
pub const _ISblank: C2RustUnnamed_12 = 1;
pub const _ISgraph: C2RustUnnamed_12 = 32768;
pub const _ISprint: C2RustUnnamed_12 = 16384;
pub const _ISspace: C2RustUnnamed_12 = 8192;
pub const _ISxdigit: C2RustUnnamed_12 = 4096;
pub const _ISdigit: C2RustUnnamed_12 = 2048;
pub const _ISalpha: C2RustUnnamed_12 = 1024;
pub const _ISlower: C2RustUnnamed_12 = 512;
pub const _ISupper: C2RustUnnamed_12 = 256;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct group {
    pub gr_name: *mut libc::c_char,
    pub gr_passwd: *mut libc::c_char,
    pub gr_gid: __gid_t,
    pub gr_mem: *mut *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dirent {
    pub d_ino: __ino_t,
    pub d_off: __off_t,
    pub d_reclen: libc::c_ushort,
    pub d_type: libc::c_uchar,
    pub d_name: [libc::c_char; 256],
}
pub type BIGNUM = bignum_st;
pub type DH = dh_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct command_struct {
    pub command_name: *mut libc::c_char,
    pub command_line: *mut libc::c_char,
    pub next: *mut command_struct,
}
pub type command = command_struct;
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
pub type SslLogging = _SSL_LOGGING;
pub type _SSL_LOGGING = libc::c_uint;
pub const SSL_LogCertDetails: _SSL_LOGGING = 32;
pub const SSL_LogIfClientCert: _SSL_LOGGING = 16;
pub const SSL_LogCipher: _SSL_LOGGING = 8;
pub const SSL_LogVersion: _SSL_LOGGING = 4;
pub const SSL_LogIpAddr: _SSL_LOGGING = 2;
pub const SSL_LogStartup: _SSL_LOGGING = 1;
pub const SSL_NoLogging: _SSL_LOGGING = 0;
pub type ClntCerts = _CLNT_CERTS;
pub type _CLNT_CERTS = libc::c_uint;
pub const Require_Cert: _CLNT_CERTS = 2;
pub const Ask_For_Cert: _CLNT_CERTS = 1;
pub const ClntCerts_Unknown: _CLNT_CERTS = 0;
pub type SslVer = _SSL_VER;
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
unsafe extern "C" fn get_dh2048() -> *mut DH {
    static mut dhp_2048: [libc::c_uchar; 256] = [
        0xea as libc::c_int as libc::c_uchar,
        0x46 as libc::c_int as libc::c_uchar,
        0xdd as libc::c_int as libc::c_uchar,
        0x48 as libc::c_int as libc::c_uchar,
        0x81 as libc::c_int as libc::c_uchar,
        0x21 as libc::c_int as libc::c_uchar,
        0x7 as libc::c_int as libc::c_uchar,
        0xb6 as libc::c_int as libc::c_uchar,
        0x31 as libc::c_int as libc::c_uchar,
        0x3e as libc::c_int as libc::c_uchar,
        0x77 as libc::c_int as libc::c_uchar,
        0x57 as libc::c_int as libc::c_uchar,
        0x2d as libc::c_int as libc::c_uchar,
        0xb as libc::c_int as libc::c_uchar,
        0xcb as libc::c_int as libc::c_uchar,
        0x3b as libc::c_int as libc::c_uchar,
        0x1c as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0xc7 as libc::c_int as libc::c_uchar,
        0xb3 as libc::c_int as libc::c_uchar,
        0xe9 as libc::c_int as libc::c_uchar,
        0xcf as libc::c_int as libc::c_uchar,
        0x1e as libc::c_int as libc::c_uchar,
        0xcd as libc::c_int as libc::c_uchar,
        0x44 as libc::c_int as libc::c_uchar,
        0x75 as libc::c_int as libc::c_uchar,
        0x64 as libc::c_int as libc::c_uchar,
        0x64 as libc::c_int as libc::c_uchar,
        0x15 as libc::c_int as libc::c_uchar,
        0xfc as libc::c_int as libc::c_uchar,
        0x5b as libc::c_int as libc::c_uchar,
        0x69 as libc::c_int as libc::c_uchar,
        0x3b as libc::c_int as libc::c_uchar,
        0xa9 as libc::c_int as libc::c_uchar,
        0xe9 as libc::c_int as libc::c_uchar,
        0xa7 as libc::c_int as libc::c_uchar,
        0xdf as libc::c_int as libc::c_uchar,
        0xea as libc::c_int as libc::c_uchar,
        0xff as libc::c_int as libc::c_uchar,
        0x5a as libc::c_int as libc::c_uchar,
        0x3b as libc::c_int as libc::c_uchar,
        0xa9 as libc::c_int as libc::c_uchar,
        0x37 as libc::c_int as libc::c_uchar,
        0x69 as libc::c_int as libc::c_uchar,
        0x3c as libc::c_int as libc::c_uchar,
        0xe1 as libc::c_int as libc::c_uchar,
        0x16 as libc::c_int as libc::c_uchar,
        0xd9 as libc::c_int as libc::c_uchar,
        0xcb as libc::c_int as libc::c_uchar,
        0x9d as libc::c_int as libc::c_uchar,
        0xe7 as libc::c_int as libc::c_uchar,
        0xc2 as libc::c_int as libc::c_uchar,
        0x5 as libc::c_int as libc::c_uchar,
        0x98 as libc::c_int as libc::c_uchar,
        0xb0 as libc::c_int as libc::c_uchar,
        0xe8 as libc::c_int as libc::c_uchar,
        0x37 as libc::c_int as libc::c_uchar,
        0x71 as libc::c_int as libc::c_uchar,
        0x48 as libc::c_int as libc::c_uchar,
        0xde as libc::c_int as libc::c_uchar,
        0xa2 as libc::c_int as libc::c_uchar,
        0xa5 as libc::c_int as libc::c_uchar,
        0xd9 as libc::c_int as libc::c_uchar,
        0x4c as libc::c_int as libc::c_uchar,
        0x4d as libc::c_int as libc::c_uchar,
        0x2c as libc::c_int as libc::c_uchar,
        0xb0 as libc::c_int as libc::c_uchar,
        0xd8 as libc::c_int as libc::c_uchar,
        0x69 as libc::c_int as libc::c_uchar,
        0x67 as libc::c_int as libc::c_uchar,
        0xd8 as libc::c_int as libc::c_uchar,
        0x62 as libc::c_int as libc::c_uchar,
        0xad as libc::c_int as libc::c_uchar,
        0xa6 as libc::c_int as libc::c_uchar,
        0xd6 as libc::c_int as libc::c_uchar,
        0x87 as libc::c_int as libc::c_uchar,
        0x1c as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0x5f as libc::c_int as libc::c_uchar,
        0x6b as libc::c_int as libc::c_uchar,
        0x59 as libc::c_int as libc::c_uchar,
        0xa5 as libc::c_int as libc::c_uchar,
        0x93 as libc::c_int as libc::c_uchar,
        0x11 as libc::c_int as libc::c_uchar,
        0x16 as libc::c_int as libc::c_uchar,
        0xf6 as libc::c_int as libc::c_uchar,
        0xfb as libc::c_int as libc::c_uchar,
        0xde as libc::c_int as libc::c_uchar,
        0xc4 as libc::c_int as libc::c_uchar,
        0xc5 as libc::c_int as libc::c_uchar,
        0xa0 as libc::c_int as libc::c_uchar,
        0xd as libc::c_int as libc::c_uchar,
        0x86 as libc::c_int as libc::c_uchar,
        0x9b as libc::c_int as libc::c_uchar,
        0x4e as libc::c_int as libc::c_uchar,
        0x28 as libc::c_int as libc::c_uchar,
        0x90 as libc::c_int as libc::c_uchar,
        0xa5 as libc::c_int as libc::c_uchar,
        0xe6 as libc::c_int as libc::c_uchar,
        0xb2 as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x39 as libc::c_int as libc::c_uchar,
        0xd1 as libc::c_int as libc::c_uchar,
        0xa9 as libc::c_int as libc::c_uchar,
        0x4e as libc::c_int as libc::c_uchar,
        0xa0 as libc::c_int as libc::c_uchar,
        0x3e as libc::c_int as libc::c_uchar,
        0xff as libc::c_int as libc::c_uchar,
        0x9e as libc::c_int as libc::c_uchar,
        0x8d as libc::c_int as libc::c_uchar,
        0xc1 as libc::c_int as libc::c_uchar,
        0x78 as libc::c_int as libc::c_uchar,
        0x45 as libc::c_int as libc::c_uchar,
        0x8b as libc::c_int as libc::c_uchar,
        0x3c as libc::c_int as libc::c_uchar,
        0xa1 as libc::c_int as libc::c_uchar,
        0x7a as libc::c_int as libc::c_uchar,
        0xcc as libc::c_int as libc::c_uchar,
        0xc7 as libc::c_int as libc::c_uchar,
        0x9a as libc::c_int as libc::c_uchar,
        0x9f as libc::c_int as libc::c_uchar,
        0xe9 as libc::c_int as libc::c_uchar,
        0x6b as libc::c_int as libc::c_uchar,
        0xa8 as libc::c_int as libc::c_uchar,
        0x4b as libc::c_int as libc::c_uchar,
        0xa4 as libc::c_int as libc::c_uchar,
        0x61 as libc::c_int as libc::c_uchar,
        0x29 as libc::c_int as libc::c_uchar,
        0x86 as libc::c_int as libc::c_uchar,
        0x60 as libc::c_int as libc::c_uchar,
        0x1e as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0x94 as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x27 as libc::c_int as libc::c_uchar,
        0x95 as libc::c_int as libc::c_uchar,
        0x3c as libc::c_int as libc::c_uchar,
        0xba as libc::c_int as libc::c_uchar,
        0xe8 as libc::c_int as libc::c_uchar,
        0x9b as libc::c_int as libc::c_uchar,
        0x1d as libc::c_int as libc::c_uchar,
        0xc0 as libc::c_int as libc::c_uchar,
        0x73 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0x64 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0x57 as libc::c_int as libc::c_uchar,
        0xc9 as libc::c_int as libc::c_uchar,
        0xf5 as libc::c_int as libc::c_uchar,
        0x67 as libc::c_int as libc::c_uchar,
        0xe0 as libc::c_int as libc::c_uchar,
        0xa4 as libc::c_int as libc::c_uchar,
        0x47 as libc::c_int as libc::c_uchar,
        0x7d as libc::c_int as libc::c_uchar,
        0xc7 as libc::c_int as libc::c_uchar,
        0x7e as libc::c_int as libc::c_uchar,
        0x52 as libc::c_int as libc::c_uchar,
        0xa0 as libc::c_int as libc::c_uchar,
        0x34 as libc::c_int as libc::c_uchar,
        0xfc as libc::c_int as libc::c_uchar,
        0x15 as libc::c_int as libc::c_uchar,
        0xeb as libc::c_int as libc::c_uchar,
        0x2b as libc::c_int as libc::c_uchar,
        0xe1 as libc::c_int as libc::c_uchar,
        0x8d as libc::c_int as libc::c_uchar,
        0x57 as libc::c_int as libc::c_uchar,
        0x5a as libc::c_int as libc::c_uchar,
        0x87 as libc::c_int as libc::c_uchar,
        0x5b as libc::c_int as libc::c_uchar,
        0x1e as libc::c_int as libc::c_uchar,
        0x63 as libc::c_int as libc::c_uchar,
        0x3 as libc::c_int as libc::c_uchar,
        0x84 as libc::c_int as libc::c_uchar,
        0x3c as libc::c_int as libc::c_uchar,
        0xf2 as libc::c_int as libc::c_uchar,
        0x38 as libc::c_int as libc::c_uchar,
        0x96 as libc::c_int as libc::c_uchar,
        0xb0 as libc::c_int as libc::c_uchar,
        0x7 as libc::c_int as libc::c_uchar,
        0x69 as libc::c_int as libc::c_uchar,
        0x3a as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x2f as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x68 as libc::c_int as libc::c_uchar,
        0xca as libc::c_int as libc::c_uchar,
        0x3d as libc::c_int as libc::c_uchar,
        0x14 as libc::c_int as libc::c_uchar,
        0x33 as libc::c_int as libc::c_uchar,
        0x12 as libc::c_int as libc::c_uchar,
        0x20 as libc::c_int as libc::c_uchar,
        0x2b as libc::c_int as libc::c_uchar,
        0xea as libc::c_int as libc::c_uchar,
        0x95 as libc::c_int as libc::c_uchar,
        0x90 as libc::c_int as libc::c_uchar,
        0x6f as libc::c_int as libc::c_uchar,
        0x78 as libc::c_int as libc::c_uchar,
        0x84 as libc::c_int as libc::c_uchar,
        0x97 as libc::c_int as libc::c_uchar,
        0xf as libc::c_int as libc::c_uchar,
        0x12 as libc::c_int as libc::c_uchar,
        0xcf as libc::c_int as libc::c_uchar,
        0x10 as libc::c_int as libc::c_uchar,
        0x4b as libc::c_int as libc::c_uchar,
        0x62 as libc::c_int as libc::c_uchar,
        0xfe as libc::c_int as libc::c_uchar,
        0x60 as libc::c_int as libc::c_uchar,
        0xd as libc::c_int as libc::c_uchar,
        0xf2 as libc::c_int as libc::c_uchar,
        0xa5 as libc::c_int as libc::c_uchar,
        0x9d as libc::c_int as libc::c_uchar,
        0x26 as libc::c_int as libc::c_uchar,
        0xad as libc::c_int as libc::c_uchar,
        0xa3 as libc::c_int as libc::c_uchar,
        0x24 as libc::c_int as libc::c_uchar,
        0x44 as libc::c_int as libc::c_uchar,
        0xdb as libc::c_int as libc::c_uchar,
        0xa2 as libc::c_int as libc::c_uchar,
        0x26 as libc::c_int as libc::c_uchar,
        0x8f as libc::c_int as libc::c_uchar,
        0x28 as libc::c_int as libc::c_uchar,
        0x6f as libc::c_int as libc::c_uchar,
        0xd9 as libc::c_int as libc::c_uchar,
        0x42 as libc::c_int as libc::c_uchar,
        0xc6 as libc::c_int as libc::c_uchar,
        0xa3 as libc::c_int as libc::c_uchar,
        0x34 as libc::c_int as libc::c_uchar,
        0x92 as libc::c_int as libc::c_uchar,
        0xa2 as libc::c_int as libc::c_uchar,
        0x1a as libc::c_int as libc::c_uchar,
        0x30 as libc::c_int as libc::c_uchar,
        0xfb as libc::c_int as libc::c_uchar,
        0xf9 as libc::c_int as libc::c_uchar,
        0x31 as libc::c_int as libc::c_uchar,
        0xea as libc::c_int as libc::c_uchar,
        0xa2 as libc::c_int as libc::c_uchar,
        0xd5 as libc::c_int as libc::c_uchar,
        0x71 as libc::c_int as libc::c_uchar,
        0x73 as libc::c_int as libc::c_uchar,
        0x68 as libc::c_int as libc::c_uchar,
        0x7c as libc::c_int as libc::c_uchar,
        0xee as libc::c_int as libc::c_uchar,
        0xbb as libc::c_int as libc::c_uchar,
        0x43 as libc::c_int as libc::c_uchar,
        0x7 as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0xca as libc::c_int as libc::c_uchar,
        0x8f as libc::c_int as libc::c_uchar,
        0xa as libc::c_int as libc::c_uchar,
        0xa7 as libc::c_int as libc::c_uchar,
        0xc8 as libc::c_int as libc::c_uchar,
        0x17 as libc::c_int as libc::c_uchar,
        0x28 as libc::c_int as libc::c_uchar,
        0xd0 as libc::c_int as libc::c_uchar,
        0x53 as libc::c_int as libc::c_uchar,
    ];
    static mut dhg_2048: [libc::c_uchar; 1] = [0x2 as libc::c_int as libc::c_uchar];
    let mut dh: *mut DH = DH_new();
    let mut p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: *mut BIGNUM = 0 as *mut BIGNUM;
    if dh.is_null() {
        return 0 as *mut DH;
    }
    p = BN_bin2bn(
        dhp_2048.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_uchar; 256]>() as libc::c_ulong as libc::c_int,
        0 as *mut BIGNUM,
    );
    g = BN_bin2bn(
        dhg_2048.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_uchar; 1]>() as libc::c_ulong as libc::c_int,
        0 as *mut BIGNUM,
    );
    if p.is_null() || g.is_null() || DH_set0_pqg(dh, p, 0 as *mut BIGNUM, g) == 0 {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return 0 as *mut DH;
    }
    return dh;
}
#[no_mangle]
pub static mut meth: *const SSL_METHOD = 0 as *const SSL_METHOD;
#[no_mangle]
pub static mut ctx: *mut SSL_CTX = 0 as *const SSL_CTX as *mut SSL_CTX;
#[no_mangle]
pub static mut use_ssl: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut listen_addrs: *mut addrinfo = 0 as *const addrinfo as *mut addrinfo;
#[no_mangle]
pub static mut listen_socks: [libc::c_int; 16] = [0; 16];
#[no_mangle]
pub static mut remote_host: [libc::c_char; 256] = [0; 256];
#[no_mangle]
pub static mut macro_argv: [*mut libc::c_char; 16] = [0 as *const libc::c_char
    as *mut libc::c_char; 16];
#[no_mangle]
pub static mut config_file: [libc::c_char; 2048] = unsafe {
    *::core::mem::transmute::<
        &[u8; 2048],
        &mut [libc::c_char; 2048],
    >(
        b"nrpe.cfg\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
};
#[no_mangle]
pub static mut server_address: [libc::c_char; 1025] = unsafe {
    *::core::mem::transmute::<
        &[u8; 1025],
        &mut [libc::c_char; 1025],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    )
};
#[no_mangle]
pub static mut command_name: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut log_facility: libc::c_int = (3 as libc::c_int) << 3 as libc::c_int;
#[no_mangle]
pub static mut server_port: libc::c_int = 5666 as libc::c_int;
#[no_mangle]
pub static mut num_listen_socks: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut address_family: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut socket_timeout: libc::c_int = 10 as libc::c_int;
#[no_mangle]
pub static mut command_timeout: libc::c_int = 60 as libc::c_int;
#[no_mangle]
pub static mut connection_timeout: libc::c_int = 300 as libc::c_int;
#[no_mangle]
pub static mut ssl_shutdown_timeout: libc::c_int = 15 as libc::c_int;
#[no_mangle]
pub static mut command_prefix: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut packet_ver: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut command_list: *mut command = 0 as *const command as *mut command;
#[no_mangle]
pub static mut nrpe_user: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut nrpe_group: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut allowed_hosts: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut keep_env_vars: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut pid_file: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
#[no_mangle]
pub static mut wrote_pid_file: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut allow_arguments: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut allow_bash_cmd_subst: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut allow_weak_random_seed: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut sigrestart: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut sigshutdown: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut show_help: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut show_license: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut show_version: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut use_inetd: libc::c_int = 1 as libc::c_int;
#[no_mangle]
pub static mut commands_running: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut max_commands: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut debug: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut use_src: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut no_forking: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut listen_queue_size: libc::c_int = 5 as libc::c_int;
#[no_mangle]
pub static mut nasty_metachars: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
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
                b"ALL:!MD5:@STRENGTH:@SECLEVEL=0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            ),
            ssl_proto_ver: TLSv1_plus,
            allowDH: 1 as libc::c_int,
            client_certs: ClntCerts_Unknown,
            log_opts: SSL_NoLogging,
        };
        init
    }
};
#[no_mangle]
pub static mut disable_syslog: libc::c_int = 0 as libc::c_int;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut x: libc::c_int = 0;
    let mut y: uint32_t = 0;
    let mut buffer: [libc::c_char; 2048] = [0; 2048];
    init();
    result = process_arguments(argc, argv);
    if result != 0 as libc::c_int || show_help == 1 as libc::c_int
        || show_license == 1 as libc::c_int || show_version == 1 as libc::c_int
    {
        usage(result);
    }
    if config_file[0 as libc::c_int as usize] as libc::c_int != '/' as i32 {
        strncpy(
            buffer.as_mut_ptr(),
            config_file.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
        );
        buffer[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
        strcpy(config_file.as_mut_ptr(), b"\0" as *const u8 as *const libc::c_char);
        if (getcwd(
            config_file.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
        ))
            .is_null()
        {
            printf(
                b"ERROR: getcwd(): %s, bailing out...\n\0" as *const u8
                    as *const libc::c_char,
                strerror(*__errno_location()),
            );
            exit(2 as libc::c_int);
        }
        strncat(
            config_file.as_mut_ptr(),
            b"/\0" as *const u8 as *const libc::c_char,
            (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(2 as libc::c_int as libc::c_ulong),
        );
        config_file[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
        strncat(
            config_file.as_mut_ptr(),
            buffer.as_mut_ptr(),
            (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(strlen(config_file.as_mut_ptr()))
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        config_file[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
    }
    result = read_config_file(config_file.as_mut_ptr());
    if result == -(1 as libc::c_int) {
        logit(
            3 as libc::c_int,
            b"Config file '%s' contained errors, aborting...\0" as *const u8
                as *const libc::c_char,
            config_file.as_mut_ptr(),
        );
        return 2 as libc::c_int;
    }
    if nasty_metachars.is_null() {
        nasty_metachars = strdup(
            b"|`&><'\\[]{};\r\n\0" as *const u8 as *const libc::c_char,
        );
    }
    x = 0 as libc::c_int;
    while x < 16 as libc::c_int {
        macro_argv[x as usize] = 0 as *mut libc::c_char;
        x += 1;
    }
    init_ssl();
    if use_inetd == 1 as libc::c_int {
        run_inetd();
    } else if use_src == 1 as libc::c_int || no_forking == 1 as libc::c_int {
        run_src();
    } else {
        run_daemon();
    }
    if use_ssl == 1 as libc::c_int {
        SSL_CTX_free(ctx);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn init() -> libc::c_int {
    let mut env_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut result: libc::c_int = 0 as libc::c_int;
    asprintf(
        &mut env_string as *mut *mut libc::c_char,
        b"NRPE_MULTILINESUPPORT=1\0" as *const u8 as *const libc::c_char,
    );
    putenv(env_string);
    asprintf(
        &mut env_string as *mut *mut libc::c_char,
        b"NRPE_PROGRAMVERSION=%s\0" as *const u8 as *const libc::c_char,
        b"4.1.0\0" as *const u8 as *const libc::c_char,
    );
    putenv(env_string);
    get_log_facility(
        b"daemon\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    openlog(
        b"nrpe\0" as *const u8 as *const libc::c_char,
        0x1 as libc::c_int,
        log_facility,
    );
    generate_crc32_table();
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn init_ssl() {
    let mut dh: *mut DH = 0 as *mut DH;
    let mut seedfile: [libc::c_char; 4096] = [0; 4096];
    let mut errstr: [libc::c_char; 120] = *::core::mem::transmute::<
        &[u8; 120],
        &mut [libc::c_char; 120],
    >(
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let mut i: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut vrfy: libc::c_int = 0;
    let mut ssl_opts: libc::c_ulong = (0x80000000 as libc::c_uint | 0x800 as libc::c_uint
        | 0x4 as libc::c_uint | 0x10 as libc::c_uint | 0x40 as libc::c_uint
        | 0 as libc::c_int as libc::c_uint) as libc::c_ulong;
    if use_ssl == 0 as libc::c_int {
        if debug == 1 as libc::c_int {
            logit(
                6 as libc::c_int,
                b"INFO: SSL/TLS NOT initialized. Network encryption DISABLED.\0"
                    as *const u8 as *const libc::c_char,
            );
        }
        return;
    }
    ssl_opts |= 0x40000000 as libc::c_uint as libc::c_ulong;
    ssl_opts |= 0x400000 as libc::c_uint as libc::c_ulong;
    if sslprm.log_opts as libc::c_uint & SSL_LogStartup as libc::c_int as libc::c_uint
        != 0
    {
        log_ssl_startup();
    }
    OPENSSL_init_ssl(
        (0x200000 as libc::c_long | 0x2 as libc::c_long) as uint64_t,
        0 as *const OPENSSL_INIT_SETTINGS,
    );
    OPENSSL_init_ssl(0 as libc::c_int as uint64_t, 0 as *const OPENSSL_INIT_SETTINGS);
    ENGINE_load_builtin_engines();
    RAND_set_rand_engine(0 as *mut ENGINE);
    ENGINE_register_all_complete();
    meth = TLS_server_method();
    if allow_weak_random_seed != 0 && RAND_status() == 0 as libc::c_int {
        if !(RAND_file_name(
            seedfile.as_mut_ptr(),
            (::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ))
            .is_null()
        {
            if RAND_load_file(seedfile.as_mut_ptr(), -(1 as libc::c_int) as libc::c_long)
                != 0
            {
                RAND_write_file(seedfile.as_mut_ptr());
            }
        }
        if RAND_status() == 0 as libc::c_int {
            logit(
                3 as libc::c_int,
                b"Warning: SSL/TLS uses a weak random seed which is highly discouraged\0"
                    as *const u8 as *const libc::c_char,
            );
            srand(time(0 as *mut time_t) as libc::c_uint);
            i = 0 as libc::c_int;
            while i < 500 as libc::c_int && RAND_status() == 0 as libc::c_int {
                c = 0 as libc::c_int;
                while (c as libc::c_ulong)
                    < ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
                {
                    *(seedfile.as_mut_ptr().offset(c as isize)
                        as *mut libc::c_int) = rand();
                    c = (c as libc::c_ulong)
                        .wrapping_add(
                            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
                        ) as libc::c_int as libc::c_int;
                }
                RAND_seed(
                    seedfile.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
                        as libc::c_int,
                );
                i += 1;
            }
        }
    }
    meth = TLS_method();
    ctx = SSL_CTX_new(meth);
    if ctx.is_null() {
        loop {
            x = ERR_get_error() as libc::c_int;
            if !(x != 0 as libc::c_int) {
                break;
            }
            ERR_error_string(x as libc::c_ulong, errstr.as_mut_ptr());
            logit(
                3 as libc::c_int,
                b"Error: could not create SSL context : %s\0" as *const u8
                    as *const libc::c_char,
                errstr.as_mut_ptr(),
            );
        }
        SSL_CTX_free(ctx);
        exit(2 as libc::c_int);
    }
    SSL_CTX_ctrl(
        ctx,
        124 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        0 as *mut libc::c_void,
    );
    let mut current_block_52: u64;
    match sslprm.ssl_proto_ver as libc::c_uint {
        11 => {
            SSL_CTX_ctrl(
                ctx,
                124 as libc::c_int,
                0x304 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
            current_block_52 = 1442010353539301400;
        }
        12 => {
            current_block_52 = 1442010353539301400;
        }
        9 => {
            SSL_CTX_ctrl(
                ctx,
                124 as libc::c_int,
                0x303 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
            current_block_52 = 6736627480741587870;
        }
        10 => {
            current_block_52 = 6736627480741587870;
        }
        7 => {
            SSL_CTX_ctrl(
                ctx,
                124 as libc::c_int,
                0x302 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
            current_block_52 = 9556477679949843150;
        }
        8 => {
            current_block_52 = 9556477679949843150;
        }
        5 => {
            SSL_CTX_ctrl(
                ctx,
                124 as libc::c_int,
                0x301 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
            current_block_52 = 10059845056013757111;
        }
        6 => {
            current_block_52 = 10059845056013757111;
        }
        3 => {
            SSL_CTX_ctrl(
                ctx,
                124 as libc::c_int,
                0x300 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
            current_block_52 = 12597762448853739353;
        }
        4 => {
            current_block_52 = 12597762448853739353;
        }
        _ => {
            current_block_52 = 3160140712158701372;
        }
    }
    match current_block_52 {
        1442010353539301400 => {
            SSL_CTX_ctrl(
                ctx,
                123 as libc::c_int,
                0x304 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
        }
        6736627480741587870 => {
            SSL_CTX_ctrl(
                ctx,
                123 as libc::c_int,
                0x303 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
        }
        9556477679949843150 => {
            SSL_CTX_ctrl(
                ctx,
                123 as libc::c_int,
                0x302 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
        }
        10059845056013757111 => {
            SSL_CTX_ctrl(
                ctx,
                123 as libc::c_int,
                0x301 as libc::c_int as libc::c_long,
                0 as *mut libc::c_void,
            );
        }
        12597762448853739353 => {
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
    if !(sslprm.cacert_file).is_null() {
        if SSL_CTX_load_verify_locations(
            ctx,
            sslprm.cacert_file,
            0 as *const libc::c_char,
        ) == 0
        {
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
                    b"Error: could not use CA certificate file '%s': %s\n\0" as *const u8
                        as *const libc::c_char,
                    sslprm.cacert_file,
                    ERR_reason_error_string(x as libc::c_ulong),
                );
            }
            SSL_CTX_free(ctx);
            logit(
                3 as libc::c_int,
                b"Error: could not use CA certificate '%s'\0" as *const u8
                    as *const libc::c_char,
                sslprm.cacert_file,
            );
            exit(2 as libc::c_int);
        }
    }
    if !(sslprm.cert_file).is_null() {
        if SSL_CTX_use_certificate_chain_file(ctx, sslprm.cert_file) == 0 {
            SSL_CTX_free(ctx);
            loop {
                x = ERR_get_error() as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                ERR_error_string(x as libc::c_ulong, errstr.as_mut_ptr());
                logit(
                    3 as libc::c_int,
                    b"Error: could not use certificate file %s : %s\0" as *const u8
                        as *const libc::c_char,
                    sslprm.cert_file,
                    errstr.as_mut_ptr(),
                );
            }
            exit(2 as libc::c_int);
        }
        if SSL_CTX_use_PrivateKey_file(ctx, sslprm.privatekey_file, 1 as libc::c_int)
            == 0
        {
            loop {
                x = ERR_get_error() as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                ERR_error_string(x as libc::c_ulong, errstr.as_mut_ptr());
                logit(
                    3 as libc::c_int,
                    b"Error: could not use private key file '%s' : %s\0" as *const u8
                        as *const libc::c_char,
                    sslprm.privatekey_file,
                    errstr.as_mut_ptr(),
                );
            }
            SSL_CTX_free(ctx);
            exit(2 as libc::c_int);
        }
        if SSL_CTX_check_private_key(ctx) == 0 {
            loop {
                x = ERR_get_error() as libc::c_int;
                if !(x != 0 as libc::c_int) {
                    break;
                }
                ERR_error_string(x as libc::c_ulong, errstr.as_mut_ptr());
                logit(
                    3 as libc::c_int,
                    b"Error: could not use certificate/private key pair: %s\0"
                        as *const u8 as *const libc::c_char,
                    errstr.as_mut_ptr(),
                );
            }
            SSL_CTX_free(ctx);
            exit(2 as libc::c_int);
        }
    }
    if sslprm.client_certs as libc::c_uint != 0 as libc::c_int as libc::c_uint {
        if (sslprm.cacert_file).is_null() {
            logit(
                3 as libc::c_int,
                b"Error: CA certificate required for client verification.\0" as *const u8
                    as *const libc::c_char,
            );
            if sslprm.client_certs as libc::c_uint
                & Require_Cert as libc::c_int as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
            {
                SSL_CTX_free(ctx);
                exit(2 as libc::c_int);
            }
        }
        vrfy = 0x1 as libc::c_int | 0x4 as libc::c_int;
        if sslprm.client_certs as libc::c_uint
            & Require_Cert as libc::c_int as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
        {
            vrfy |= 0x2 as libc::c_int;
        }
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
        }
    } else {
        if sslprm.allowDH == 2 as libc::c_int {
            strncpy(
                (sslprm.cipher_list).as_mut_ptr(),
                b"ADH@SECLEVEL=0\0" as *const u8 as *const libc::c_char,
                (256 as libc::c_int - 1 as libc::c_int) as libc::c_ulong,
            );
        }
        dh = get_dh2048();
        SSL_CTX_ctrl(
            ctx,
            3 as libc::c_int,
            0 as libc::c_int as libc::c_long,
            dh as *mut libc::c_char as *mut libc::c_void,
        );
        DH_free(dh);
    }
    if SSL_CTX_set_cipher_list(ctx, (sslprm.cipher_list).as_mut_ptr())
        == 0 as libc::c_int
    {
        SSL_CTX_free(ctx);
        logit(
            3 as libc::c_int,
            b"Error: Could not set SSL/TLS cipher list\0" as *const u8
                as *const libc::c_char,
        );
        exit(2 as libc::c_int);
    }
    if debug == 1 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"INFO: SSL/TLS initialized. All network traffic will be encrypted.\0"
                as *const u8 as *const libc::c_char,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn log_ssl_startup() {
    let mut vers: *mut libc::c_char = 0 as *mut libc::c_char;
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
        (sslprm.allowDH == 0 as libc::c_int) as libc::c_int,
    );
    logit(
        6 as libc::c_int,
        b"SSL Client Certs: %s\0" as *const u8 as *const libc::c_char,
        if sslprm.client_certs as libc::c_uint == 0 as libc::c_int as libc::c_uint {
            b"Don't Ask\0" as *const u8 as *const libc::c_char
        } else if sslprm.client_certs as libc::c_uint == 1 as libc::c_int as libc::c_uint
        {
            b"Accept\0" as *const u8 as *const libc::c_char
        } else {
            b"Require\0" as *const u8 as *const libc::c_char
        },
    );
    logit(
        6 as libc::c_int,
        b"SSL Log Options: 0x%02x\0" as *const u8 as *const libc::c_char,
        sslprm.log_opts as libc::c_uint,
    );
    match sslprm.ssl_proto_ver as libc::c_uint {
        1 => {
            vers = b"SSLv2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        2 => {
            vers = b"SSLv2 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        3 => {
            vers = b"SSLv3\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        4 => {
            vers = b"SSLv3 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        5 => {
            vers = b"TLSv1\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        6 => {
            vers = b"TLSv1 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        7 => {
            vers = b"TLSv1_1\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        8 => {
            vers = b"TLSv1_1 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        9 => {
            vers = b"TLSv1_2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        10 => {
            vers = b"TLSv1_2 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        11 => {
            vers = b"TLSv1_3\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        12 => {
            vers = b"TLSv1_3 And Above\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        _ => {
            vers = b"INVALID VALUE!\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
    }
    logit(
        6 as libc::c_int,
        b"SSL Version: %s\0" as *const u8 as *const libc::c_char,
        vers,
    );
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
    printf(
        b"NRPE - Nagios Remote Plugin Executor\n\0" as *const u8 as *const libc::c_char,
    );
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
            b"SSL/TLS Available, OpenSSL 0.9.6 or higher required\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"***************************************************************\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"** POSSIBLE SECURITY RISK - TCP WRAPPERS ARE NOT AVAILABLE!  **\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"**      Read the NRPE SECURITY file for more information     **\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"***************************************************************\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"Usage: nrpe [-V] [-n] -c <config_file> [-4|-6] <mode>\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(b"Options:\n\0" as *const u8 as *const libc::c_char);
        printf(
            b" -V, --version         Print version info and quit\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -n, --no-ssl          Do not use SSL\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -c, --config=FILE     Name of config file to use\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -4, --ipv4            Use ipv4 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" -6, --ipv6            Use ipv6 only\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b" <mode> (One of the following operating modes)\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"   -i, --inetd         Run as a service under inetd or xinetd\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"   -d, --daemon        Run as a standalone daemon\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"   -s, --src           Run as a subsystem under AIX\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"   -f, --no-forking    Don't fork() (for systemd, launchd, etc.)\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(b"\n\0" as *const u8 as *const libc::c_char);
        printf(b"Notes:\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"This program is designed to process requests from the check_nrpe\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"plugin on the host(s) running Nagios.  It can run as a service\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"under inetd or xinetd (read the docs for info on this), or as a\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"standalone daemon. Once a request is received from an authorized\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"host, NRPE will execute the command/plugin (as defined in the\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(
            b"config file) and return the plugin output and return code to the\n\0"
                as *const u8 as *const libc::c_char,
        );
        printf(b"check_nrpe plugin.\n\0" as *const u8 as *const libc::c_char);
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
    if show_license == 1 as libc::c_int {
        display_license();
    }
    exit(3 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn run_inetd() {
    check_privileges();
    close(2 as libc::c_int);
    open(b"/dev/null\0" as *const u8 as *const libc::c_char, 0o1 as libc::c_int);
    handle_connection(0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn run_src() {
    set_stdio_sigs();
    loop {
        sigrestart = 0 as libc::c_int;
        sigshutdown = 0 as libc::c_int;
        wait_for_connections();
        cleanup();
        if !(sigrestart == 1 as libc::c_int && sigshutdown == 0 as libc::c_int) {
            break;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn run_daemon() {
    let mut pid: pid_t = 0;
    pid = fork();
    if pid != 0 as libc::c_int {
        if pid == -(1 as libc::c_int) {
            logit(
                3 as libc::c_int,
                b"fork() failed with error %d, bailing out...\0" as *const u8
                    as *const libc::c_char,
                *__errno_location(),
            );
            exit(2 as libc::c_int);
        }
        return;
    }
    setsid();
    set_stdio_sigs();
    loop {
        sigrestart = 0 as libc::c_int;
        sigshutdown = 0 as libc::c_int;
        wait_for_connections();
        cleanup();
        if !(sigrestart == 1 as libc::c_int && sigshutdown == 0 as libc::c_int) {
            break;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn set_stdio_sigs() {
    let mut sig_action: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    if chdir(b"/\0" as *const u8 as *const libc::c_char) == -(1 as libc::c_int) {
        printf(
            b"ERROR: chdir(): %s, bailing out...\n\0" as *const u8
                as *const libc::c_char,
            strerror(*__errno_location()),
        );
        exit(2 as libc::c_int);
    }
    close(0 as libc::c_int);
    close(1 as libc::c_int);
    close(2 as libc::c_int);
    open(b"/dev/null\0" as *const u8 as *const libc::c_char, 0 as libc::c_int);
    open(b"/dev/null\0" as *const u8 as *const libc::c_char, 0o1 as libc::c_int);
    open(b"/dev/null\0" as *const u8 as *const libc::c_char, 0o1 as libc::c_int);
    sig_action.__sigaction_handler.sa_sigaction = None;
    sig_action
        .__sigaction_handler
        .sa_handler = Some(sighandler as unsafe extern "C" fn(libc::c_int) -> ());
    sigfillset(&mut sig_action.sa_mask);
    sig_action.sa_flags = 0x40000000 as libc::c_int | 0x10000000 as libc::c_int;
    sigaction(3 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    sigaction(15 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    sigaction(1 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    logit(5 as libc::c_int, b"Starting up daemon\0" as *const u8 as *const libc::c_char);
    if write_pid_file() == -(1 as libc::c_int) {
        exit(2 as libc::c_int);
    }
    clean_environ(keep_env_vars, nrpe_user);
    drop_privileges(nrpe_user, nrpe_group, 0 as libc::c_int);
    check_privileges();
}
#[no_mangle]
pub unsafe extern "C" fn cleanup() {
    let mut result: libc::c_int = 0;
    free_memory();
    if sigrestart == 1 as libc::c_int && sigshutdown == 0 as libc::c_int {
        close_log_file();
        result = read_config_file(config_file.as_mut_ptr());
        if result == -(1 as libc::c_int) {
            logit(
                3 as libc::c_int,
                b"Config file '%s' contained errors, bailing out...\0" as *const u8
                    as *const libc::c_char,
                config_file.as_mut_ptr(),
            );
            exit(2 as libc::c_int);
        }
        return;
    }
    remove_pid_file();
    logit(5 as libc::c_int, b"Daemon shutdown\n\0" as *const u8 as *const libc::c_char);
    close_log_file();
}
unsafe extern "C" fn verify_callback(
    mut preverify_ok: libc::c_int,
    mut ctx_0: *mut X509_STORE_CTX,
) -> libc::c_int {
    let mut name: [libc::c_char; 256] = [0; 256];
    let mut issuer: [libc::c_char; 256] = [0; 256];
    let mut err_cert: *mut X509 = 0 as *mut X509;
    let mut err: libc::c_int = 0;
    let mut ssl: *mut SSL = 0 as *mut SSL;
    if preverify_ok != 0
        || sslprm.log_opts as libc::c_uint
            & SSL_LogCertDetails as libc::c_int as libc::c_uint
            == 0 as libc::c_int as libc::c_uint
    {
        return preverify_ok;
    }
    err_cert = X509_STORE_CTX_get_current_cert(ctx_0);
    err = X509_STORE_CTX_get_error(ctx_0);
    ssl = X509_STORE_CTX_get_ex_data(ctx_0, SSL_get_ex_data_X509_STORE_CTX_idx())
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
pub unsafe extern "C" fn process_metachars(
    mut input: *const libc::c_char,
) -> *mut libc::c_char {
    let mut copy: *mut libc::c_char = strdup(input);
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut length: libc::c_int = strlen(input) as libc::c_int;
    i = 0 as libc::c_int;
    j = 0 as libc::c_int;
    while j < length {
        if *copy.offset(j as isize) as libc::c_int != '\\' as i32 {
            *copy.offset(i as isize) = *copy.offset(j as isize);
        } else {
            j += 1 as libc::c_int;
            match *copy.offset(j as isize) as libc::c_int {
                97 => {
                    *copy.offset(i as isize) = '\u{7}' as i32 as libc::c_char;
                }
                98 => {
                    *copy.offset(i as isize) = '\u{8}' as i32 as libc::c_char;
                }
                102 => {
                    *copy.offset(i as isize) = '\u{c}' as i32 as libc::c_char;
                }
                110 => {
                    *copy.offset(i as isize) = '\n' as i32 as libc::c_char;
                }
                114 => {
                    *copy.offset(i as isize) = '\r' as i32 as libc::c_char;
                }
                116 => {
                    *copy.offset(i as isize) = '\t' as i32 as libc::c_char;
                }
                118 => {
                    *copy.offset(i as isize) = '\u{b}' as i32 as libc::c_char;
                }
                92 => {
                    *copy.offset(i as isize) = '\\' as i32 as libc::c_char;
                }
                39 => {
                    *copy.offset(i as isize) = '\'' as i32 as libc::c_char;
                }
                34 => {
                    *copy.offset(i as isize) = '"' as i32 as libc::c_char;
                }
                63 => {
                    *copy.offset(i as isize) = '?' as i32 as libc::c_char;
                }
                _ => {}
            }
        }
        i += 1;
        j += 1;
    }
    *copy.offset(i as isize) = '\0' as i32 as libc::c_char;
    return copy;
}
#[no_mangle]
pub unsafe extern "C" fn read_config_file(
    mut filename: *mut libc::c_char,
) -> libc::c_int {
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
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut config_file_0: [libc::c_char; 256] = [0; 256];
    let mut input_buffer: [libc::c_char; 2048] = [0; 2048];
    let mut input_line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut temp_buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut varname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut varvalue: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: libc::c_int = 0 as libc::c_int;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut x: libc::c_int = 0 as libc::c_int;
    fp = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
    if fp.is_null() {
        logit(
            3 as libc::c_int,
            b"Unable to open config file '%s' for reading\n\0" as *const u8
                as *const libc::c_char,
            filename,
        );
        return -(1 as libc::c_int);
    }
    while !(fgets(input_buffer.as_mut_ptr(), 2048 as libc::c_int - 1 as libc::c_int, fp))
        .is_null()
    {
        line += 1;
        input_line = input_buffer.as_mut_ptr();
        while *(*__ctype_b_loc()).offset(*input_line as libc::c_int as isize)
            as libc::c_int & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
            != 0
        {
            input_line = input_line.offset(1);
        }
        len = strlen(input_line) as libc::c_int;
        x = len - 1 as libc::c_int;
        while x >= 0 as libc::c_int {
            if !(*(*__ctype_b_loc())
                .offset(*input_line.offset(x as isize) as libc::c_int as isize)
                as libc::c_int & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                != 0)
            {
                break;
            }
            *input_line.offset(x as isize) = '\0' as i32 as libc::c_char;
            x -= 1;
        }
        if *input_line.offset(0 as libc::c_int as isize) as libc::c_int == '#' as i32
            || *input_line.offset(0 as libc::c_int as isize) as libc::c_int
                == '\0' as i32
            || *input_line.offset(0 as libc::c_int as isize) as libc::c_int
                == '\n' as i32
        {
            continue;
        }
        varname = strtok(input_line, b"=\0" as *const u8 as *const libc::c_char);
        if varname.is_null() {
            logit(
                3 as libc::c_int,
                b"No variable name specified in config file '%s' - Line %d\n\0"
                    as *const u8 as *const libc::c_char,
                filename,
                line,
            );
            return -(1 as libc::c_int);
        }
        varvalue = strtok(
            0 as *mut libc::c_char,
            b"\n\0" as *const u8 as *const libc::c_char,
        );
        if varvalue.is_null() {
            logit(
                3 as libc::c_int,
                b"No variable value specified in config file '%s' - Line %d\n\0"
                    as *const u8 as *const libc::c_char,
                filename,
                line,
            );
            return -(1 as libc::c_int);
        } else if strcmp(varname, b"include_dir\0" as *const u8 as *const libc::c_char)
            == 0
        {
            strncpy(
                config_file_0.as_mut_ptr(),
                varvalue,
                (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            config_file_0[(::core::mem::size_of::<[libc::c_char; 256]>()
                as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
            if config_file_0[(strlen(config_file_0.as_mut_ptr()))
                .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize] as libc::c_int
                == '/' as i32
            {
                config_file_0[(strlen(config_file_0.as_mut_ptr()))
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as usize] = '\0' as i32 as libc::c_char;
            }
            if read_config_dir(config_file_0.as_mut_ptr()) == -(1 as libc::c_int) {
                logit(
                    3 as libc::c_int,
                    b"Continuing with errors...\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strcmp(varname, b"include\0" as *const u8 as *const libc::c_char) == 0
            || strcmp(varname, b"include_file\0" as *const u8 as *const libc::c_char)
                == 0
        {
            if read_config_file(varvalue) == -(1 as libc::c_int) {
                logit(
                    3 as libc::c_int,
                    b"Continuing with errors...\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if strcmp(varname, b"max_commands\0" as *const u8 as *const libc::c_char)
            == 0
        {
            max_commands = atoi(varvalue);
            if max_commands < 0 as libc::c_int {
                logit(
                    4 as libc::c_int,
                    b"max_commands set too low, setting to 0\n\0" as *const u8
                        as *const libc::c_char,
                );
                max_commands = 0 as libc::c_int;
            }
        } else if strcmp(varname, b"server_port\0" as *const u8 as *const libc::c_char)
            == 0
        {
            server_port = atoi(varvalue);
            if server_port < 1024 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid port number specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(
            varname,
            b"command_prefix\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            command_prefix = strdup(varvalue);
        } else if strcmp(
            varname,
            b"server_address\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            strncpy(
                server_address.as_mut_ptr(),
                varvalue,
                (::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            server_address[(::core::mem::size_of::<[libc::c_char; 1025]>()
                as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
        } else if strcmp(varname, b"allowed_hosts\0" as *const u8 as *const libc::c_char)
            == 0
        {
            allowed_hosts = strdup(varvalue);
            parse_allowed_hosts(allowed_hosts);
            if debug == 1 as libc::c_int {
                show_acl_lists();
            }
        } else if !(strstr(
            input_line,
            b"command[\0" as *const u8 as *const libc::c_char,
        ))
            .is_null()
        {
            temp_buffer = strtok(varname, b"[\0" as *const u8 as *const libc::c_char);
            temp_buffer = strtok(
                0 as *mut libc::c_char,
                b"]\0" as *const u8 as *const libc::c_char,
            );
            if temp_buffer.is_null() {
                logit(
                    3 as libc::c_int,
                    b"Invalid command specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
            add_command(temp_buffer, varvalue);
        } else if !(strstr(
            input_buffer.as_mut_ptr(),
            b"debug\0" as *const u8 as *const libc::c_char,
        ))
            .is_null()
        {
            debug = atoi(varvalue);
            if debug > 0 as libc::c_int {
                debug = 1 as libc::c_int;
            } else {
                debug = 0 as libc::c_int;
            }
        } else if strcmp(varname, b"nrpe_user\0" as *const u8 as *const libc::c_char)
            == 0
        {
            nrpe_user = strdup(varvalue);
        } else if strcmp(varname, b"nrpe_group\0" as *const u8 as *const libc::c_char)
            == 0
        {
            nrpe_group = strdup(varvalue);
        } else if strcmp(
            varname,
            b"dont_blame_nrpe\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            allow_arguments = if atoi(varvalue) == 1 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            };
        } else if strcmp(
            varname,
            b"disable_syslog\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            disable_syslog = if atoi(varvalue) == 1 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            };
        } else if strcmp(
            varname,
            b"allow_bash_command_substitution\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            allow_bash_cmd_subst = if atoi(varvalue) == 1 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            };
        } else if strcmp(
            varname,
            b"command_timeout\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            command_timeout = atoi(varvalue);
            if command_timeout < 1 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid command_timeout specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(
            varname,
            b"connection_timeout\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            connection_timeout = atoi(varvalue);
            if connection_timeout < 1 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid connection_timeout specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(
            varname,
            b"ssl_shutdown_timeout\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            ssl_shutdown_timeout = atoi(varvalue);
            if ssl_shutdown_timeout < 1 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid ssl_shutdown_timeout specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(
            varname,
            b"allow_weak_random_seed\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            allow_weak_random_seed = if atoi(varvalue) == 1 as libc::c_int {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            };
        } else if strcmp(varname, b"pid_file\0" as *const u8 as *const libc::c_char) == 0
        {
            pid_file = strdup(varvalue);
        } else if strcmp(
            varname,
            b"listen_queue_size\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            listen_queue_size = atoi(varvalue);
            if listen_queue_size == 0 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid listen queue size specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(varname, b"ssl_version\0" as *const u8 as *const libc::c_char)
            == 0
        {
            if strcmp(varvalue, b"TLSv1.3\0" as *const u8 as *const libc::c_char) == 0 {
                sslprm.ssl_proto_ver = TLSv1_3;
            } else if strcmp(varvalue, b"TLSv1.3+\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_3_plus;
            } else if strcmp(varvalue, b"TLSv1.2\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_2;
            } else if strcmp(varvalue, b"TLSv1.2+\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_2_plus;
            } else if strcmp(varvalue, b"TLSv1.1\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_1;
            } else if strcmp(varvalue, b"TLSv1.1+\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_1_plus;
            } else if strcmp(varvalue, b"TLSv1\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1;
            } else if strcmp(varvalue, b"TLSv1+\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = TLSv1_plus;
            } else if strcmp(varvalue, b"SSLv3\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = SSLv3;
            } else if strcmp(varvalue, b"SSLv3+\0" as *const u8 as *const libc::c_char)
                == 0
            {
                sslprm.ssl_proto_ver = SSLv3_plus;
            } else {
                logit(
                    3 as libc::c_int,
                    b"Invalid ssl version specified in config file '%s' - Line %d\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(varname, b"ssl_use_adh\0" as *const u8 as *const libc::c_char)
            == 0
        {
            sslprm.allowDH = atoi(varvalue);
            if sslprm.allowDH < 0 as libc::c_int || sslprm.allowDH > 2 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Invalid use adh value specified in config file '%s' - Line %d\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
        } else if strcmp(varname, b"ssl_logging\0" as *const u8 as *const libc::c_char)
            == 0
        {
            sslprm
                .log_opts = strtoul(
                varvalue,
                0 as *mut *mut libc::c_char,
                0 as libc::c_int,
            ) as SslLogging;
        } else if strcmp(
            varname,
            b"ssl_cipher_list\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            strncpy(
                (sslprm.cipher_list).as_mut_ptr(),
                varvalue,
                (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            sslprm
                .cipher_list[(::core::mem::size_of::<[libc::c_char; 256]>()
                as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
        } else if strcmp(varname, b"ssl_cert_file\0" as *const u8 as *const libc::c_char)
            == 0
        {
            sslprm.cert_file = strdup(varvalue);
        } else if strcmp(
            varname,
            b"ssl_cacert_file\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            sslprm.cacert_file = strdup(varvalue);
        } else if strcmp(
            varname,
            b"ssl_privatekey_file\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            sslprm.privatekey_file = strdup(varvalue);
        } else if strcmp(
            varname,
            b"ssl_client_certs\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            sslprm.client_certs = atoi(varvalue) as ClntCerts;
            if (sslprm.client_certs as libc::c_int) < 0 as libc::c_int
                || sslprm.client_certs as libc::c_uint
                    > Require_Cert as libc::c_int as libc::c_uint
            {
                logit(
                    3 as libc::c_int,
                    b"Invalid client certs value specified in config file '%s' - Line %d\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
                return -(1 as libc::c_int);
            }
            if sslprm.client_certs as libc::c_uint
                & Require_Cert as libc::c_int as libc::c_uint != 0
            {
                sslprm
                    .client_certs = ::core::mem::transmute::<
                    libc::c_uint,
                    ClntCerts,
                >(
                    sslprm.client_certs as libc::c_uint
                        | Ask_For_Cert as libc::c_int as libc::c_uint,
                );
            }
        } else if strcmp(varname, b"log_facility\0" as *const u8 as *const libc::c_char)
            == 0
        {
            if get_log_facility(varvalue) == 0 as libc::c_int {
                closelog();
                openlog(
                    b"nrpe\0" as *const u8 as *const libc::c_char,
                    0x1 as libc::c_int,
                    log_facility,
                );
            } else {
                logit(
                    4 as libc::c_int,
                    b"Invalid log_facility specified in config file '%s' - Line %d\n\0"
                        as *const u8 as *const libc::c_char,
                    filename,
                    line,
                );
            }
        } else if strcmp(varname, b"keep_env_vars\0" as *const u8 as *const libc::c_char)
            == 0
        {
            keep_env_vars = strdup(varvalue);
        } else if strcmp(
            varname,
            b"nasty_metachars\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
            nasty_metachars = process_metachars(varvalue);
        } else if strcmp(varname, b"log_file\0" as *const u8 as *const libc::c_char) == 0
        {
            log_file = strdup(varvalue);
            open_log_file();
        } else {
            logit(
                4 as libc::c_int,
                b"Unknown option specified in config file '%s' - Line %d\n\0"
                    as *const u8 as *const libc::c_char,
                filename,
                line,
            );
        }
    }
    fclose(fp);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn read_config_dir(mut dirname: *mut libc::c_char) -> libc::c_int {
    let mut dirfile: *mut dirent = 0 as *mut dirent;
    let mut dirfiles: *mut *mut dirent = 0 as *mut *mut dirent;
    let mut x: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut buf: stat = stat {
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
    let mut config_file_0: [libc::c_char; 256] = [0; 256];
    let mut result: libc::c_int = 0 as libc::c_int;
    n = scandir(
        dirname,
        &mut dirfiles,
        None,
        Some(
            alphasort
                as unsafe extern "C" fn(
                    *mut *const dirent,
                    *mut *const dirent,
                ) -> libc::c_int,
        ),
    );
    if n < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Could not open config directory '%s' for reading.\n\0" as *const u8
                as *const libc::c_char,
            dirname,
        );
        return -(1 as libc::c_int);
    }
    let mut current_block_12: u64;
    i = 0 as libc::c_int;
    while i < n {
        dirfile = *dirfiles.offset(i as isize);
        snprintf(
            config_file_0.as_mut_ptr(),
            (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            dirname,
            ((*dirfile).d_name).as_mut_ptr(),
        );
        config_file_0[(::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
        stat(config_file_0.as_mut_ptr(), &mut buf);
        x = strlen(((*dirfile).d_name).as_mut_ptr()) as libc::c_int;
        if x > 4 as libc::c_int
            && strcmp(
                ((*dirfile).d_name).as_mut_ptr().offset((x - 4 as libc::c_int) as isize),
                b".cfg\0" as *const u8 as *const libc::c_char,
            ) == 0
        {
            if !(buf.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o100000 as libc::c_int as libc::c_uint)
            {
                current_block_12 = 15619007995458559411;
            } else {
                result |= read_config_file(config_file_0.as_mut_ptr());
                current_block_12 = 13586036798005543211;
            }
        } else {
            current_block_12 = 13586036798005543211;
        }
        match current_block_12 {
            13586036798005543211 => {
                if buf.st_mode & 0o170000 as libc::c_int as libc::c_uint
                    == 0o40000 as libc::c_int as libc::c_uint
                {
                    if !((*dirfile).d_name[0 as libc::c_int as usize] as libc::c_int
                        == '.' as i32)
                    {
                        result |= read_config_dir(config_file_0.as_mut_ptr());
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    i = 0 as libc::c_int;
    while i < n {
        free(*dirfiles.offset(i as isize) as *mut libc::c_void);
        i += 1;
    }
    free(dirfiles as *mut libc::c_void);
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn get_log_facility(
    mut varvalue: *mut libc::c_char,
) -> libc::c_int {
    if strcmp(varvalue, b"kern\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (0 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"user\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (1 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"mail\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (2 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"daemon\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (3 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"auth\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (4 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"syslog\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (5 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"lrp\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (6 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"news\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (7 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"uucp\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (8 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"cron\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (9 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"authpriv\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (10 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"ftp\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (11 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local0\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (16 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local1\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (17 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local2\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (18 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local3\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (19 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local4\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (20 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local5\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (21 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local6\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (22 as libc::c_int) << 3 as libc::c_int;
    } else if strcmp(varvalue, b"local7\0" as *const u8 as *const libc::c_char) == 0 {
        log_facility = (23 as libc::c_int) << 3 as libc::c_int;
    } else {
        log_facility = (3 as libc::c_int) << 3 as libc::c_int;
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn add_command(
    mut command_name_0: *mut libc::c_char,
    mut command_line: *mut libc::c_char,
) -> libc::c_int {
    let mut new_command: *mut command = 0 as *mut command;
    if command_name_0.is_null() || command_line.is_null() {
        return -(1 as libc::c_int);
    }
    new_command = malloc(::core::mem::size_of::<command>() as libc::c_ulong)
        as *mut command;
    if new_command.is_null() {
        return -(1 as libc::c_int);
    }
    (*new_command).command_name = strdup(command_name_0);
    if ((*new_command).command_name).is_null() {
        free(new_command as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*new_command).command_line = strdup(command_line);
    if ((*new_command).command_line).is_null() {
        free((*new_command).command_name as *mut libc::c_void);
        free(new_command as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*new_command).next = command_list;
    command_list = new_command;
    if debug == 1 as libc::c_int {
        logit(
            7 as libc::c_int,
            b"Added command[%s]=%s\n\0" as *const u8 as *const libc::c_char,
            command_name_0,
            command_line,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn find_command(
    mut command_name_0: *mut libc::c_char,
) -> *mut command {
    let mut temp_command: *mut command = 0 as *mut command;
    temp_command = command_list;
    while !temp_command.is_null() {
        if strcmp(command_name_0, (*temp_command).command_name) == 0 {
            return temp_command;
        }
        temp_command = (*temp_command).next;
    }
    return 0 as *mut command;
}
#[no_mangle]
pub unsafe extern "C" fn create_listener(mut ai: *mut addrinfo) {
    let mut ret: libc::c_int = 0;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut listen_sock: libc::c_int = 0;
    let mut flag: libc::c_int = 1 as libc::c_int;
    if (*ai).ai_family != 2 as libc::c_int && (*ai).ai_family != 10 as libc::c_int {
        return;
    }
    if num_listen_socks >= 16 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Too many listen sockets. Enlarge MAX_LISTEN_SOCKS\0" as *const u8
                as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    ret = getnameinfo(
        (*ai).ai_addr,
        (*ai).ai_addrlen,
        ntop.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as socklen_t,
        1 as libc::c_int | 2 as libc::c_int,
    );
    if ret != 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"getnameinfo failed: %.100s\0" as *const u8 as *const libc::c_char,
            gai_strerror(ret),
        );
        return;
    }
    listen_sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
    if listen_sock < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return;
    }
    fcntl(listen_sock, 4 as libc::c_int, 0o4000 as libc::c_int);
    if setsockopt(
        listen_sock,
        1 as libc::c_int,
        2 as libc::c_int,
        &mut flag as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) < 0 as libc::c_int
    {
        logit(
            3 as libc::c_int,
            b"setsockopt SO_REUSEADDR: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return;
    }
    if (*ai).ai_family == 10 as libc::c_int {
        if setsockopt(
            listen_sock,
            IPPROTO_IPV6 as libc::c_int,
            26 as libc::c_int,
            &mut flag as *mut libc::c_int as *const libc::c_void,
            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
        ) == -(1 as libc::c_int)
        {
            fprintf(
                stderr,
                b"setsockopt IPV6_V6ONLY: %s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
        }
    }
    if bind(listen_sock, (*ai).ai_addr, (*ai).ai_addrlen) < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Bind to port %s on %s failed: %.200s.\0" as *const u8
                as *const libc::c_char,
            strport.as_mut_ptr(),
            ntop.as_mut_ptr(),
            strerror(*__errno_location()),
        );
        close(listen_sock);
        return;
    }
    listen_socks[num_listen_socks as usize] = listen_sock;
    num_listen_socks += 1;
    if listen(listen_sock, listen_queue_size) < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"listen on [%s]:%s: %.100s\0" as *const u8 as *const libc::c_char,
            ntop.as_mut_ptr(),
            strport.as_mut_ptr(),
            strerror(*__errno_location()),
        );
        exit(1 as libc::c_int);
    }
    logit(
        6 as libc::c_int,
        b"Server listening on %s port %s.\0" as *const u8 as *const libc::c_char,
        ntop.as_mut_ptr(),
        strport.as_mut_ptr(),
    );
}
unsafe extern "C" fn close_listen_socks() {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i <= num_listen_socks {
        close(listen_socks[i as usize]);
        num_listen_socks -= 1;
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn wait_for_connections() {
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t = 0;
    let mut fdset: *mut fd_set = 0 as *mut fd_set;
    let mut maxfd: libc::c_int = 0 as libc::c_int;
    let mut new_sd: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut rc: libc::c_int = 0;
    let mut retval: libc::c_int = 0;
    setup_wait_conn();
    while !(sigrestart == 1 as libc::c_int || sigshutdown == 1 as libc::c_int) {
        i = 0 as libc::c_int;
        while i < num_listen_socks {
            if listen_socks[i as usize] > maxfd {
                maxfd = listen_socks[i as usize];
            }
            i += 1;
        }
        if !fdset.is_null() {
            free(fdset as *mut libc::c_void);
        }
        fdset = calloc(
            ((maxfd + 1 as libc::c_int
                + (8 as libc::c_int
                    * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong as libc::c_int
                    - 1 as libc::c_int))
                / (8 as libc::c_int
                    * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                        as libc::c_int)) as libc::c_ulong,
            ::core::mem::size_of::<fd_mask>() as libc::c_ulong,
        ) as *mut fd_set;
        i = 0 as libc::c_int;
        while i < num_listen_socks {
            (*fdset)
                .__fds_bits[(listen_socks[i as usize]
                / (8 as libc::c_int
                    * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                        as libc::c_int)) as usize]
                |= ((1 as libc::c_ulong)
                    << listen_socks[i as usize]
                        % (8 as libc::c_int
                            * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                                as libc::c_int)) as __fd_mask;
            i += 1;
        }
        retval = select(
            maxfd + 1 as libc::c_int,
            fdset,
            0 as *mut fd_set,
            0 as *mut fd_set,
            0 as *mut timeval,
        );
        if sigrestart == 1 as libc::c_int || sigshutdown == 1 as libc::c_int {
            break;
        }
        if retval < 0 as libc::c_int {
            continue;
        }
        i = 0 as libc::c_int;
        while i < num_listen_socks {
            if (*fdset)
                .__fds_bits[(listen_socks[i as usize]
                / (8 as libc::c_int
                    * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                        as libc::c_int)) as usize]
                & ((1 as libc::c_ulong)
                    << listen_socks[i as usize]
                        % (8 as libc::c_int
                            * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                                as libc::c_int)) as __fd_mask
                != 0 as libc::c_int as libc::c_long
            {
                fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong
                    as socklen_t;
                new_sd = accept(
                    listen_socks[i as usize],
                    &mut from as *mut sockaddr_storage as *mut sockaddr,
                    &mut fromlen,
                );
                if new_sd < 0 as libc::c_int {
                    if sigrestart == 1 as libc::c_int || sigshutdown == 1 as libc::c_int
                    {
                        break;
                    }
                    if !(*__errno_location() == 11 as libc::c_int
                        || *__errno_location() == 4 as libc::c_int)
                    {
                        if !(*__errno_location() == 11 as libc::c_int) {
                            if !(*__errno_location() == 105 as libc::c_int) {
                                break;
                            }
                        }
                    }
                } else {
                    rc = wait_conn_fork(new_sd);
                    if !(rc == 1 as libc::c_int) {
                        conn_check_peer(new_sd);
                        handle_connection(new_sd);
                        if debug == 1 as libc::c_int {
                            logit(
                                7 as libc::c_int,
                                b"Connection from %s closed.\0" as *const u8
                                    as *const libc::c_char,
                                remote_host.as_mut_ptr(),
                            );
                        }
                        close(new_sd);
                        exit(0 as libc::c_int);
                    }
                }
            }
            i += 1;
        }
    }
    close_listen_socks();
    freeaddrinfo(listen_addrs);
    listen_addrs = 0 as *mut addrinfo;
}
#[no_mangle]
pub unsafe extern "C" fn setup_wait_conn() {
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut addrstr: [libc::c_char; 100] = [0; 100];
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    add_listen_addr(
        &mut listen_addrs,
        address_family,
        if strcmp(server_address.as_mut_ptr(), b"\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            0 as *mut libc::c_char
        } else {
            server_address.as_mut_ptr()
        },
        server_port,
    );
    ai = listen_addrs;
    while !ai.is_null() {
        if debug == 1 as libc::c_int {
            inet_ntop(
                (*ai).ai_family,
                ((*(*ai).ai_addr).sa_data).as_mut_ptr() as *const libc::c_void,
                addrstr.as_mut_ptr(),
                100 as libc::c_int as socklen_t,
            );
            ptr = &mut (*((*ai).ai_addr as *mut sockaddr_in)).sin_addr as *mut in_addr
                as *mut libc::c_void;
            inet_ntop(
                (*ai).ai_family,
                ptr,
                addrstr.as_mut_ptr(),
                100 as libc::c_int as socklen_t,
            );
            logit(
                6 as libc::c_int,
                b"SETUP_WAIT_CONN FOR: IPv4 address: %s (%s)\n\0" as *const u8
                    as *const libc::c_char,
                addrstr.as_mut_ptr(),
                (*ai).ai_canonname,
            );
        }
        create_listener(ai);
        ai = (*ai).ai_next;
    }
    if num_listen_socks == 0 {
        logit(
            3 as libc::c_int,
            b"Cannot bind to any address.\0" as *const u8 as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    logit(
        6 as libc::c_int,
        b"Listening for connections on port %d\0" as *const u8 as *const libc::c_char,
        server_port,
    );
    if !allowed_hosts.is_null() {
        logit(
            6 as libc::c_int,
            b"Allowing connections from: %s\n\0" as *const u8 as *const libc::c_char,
            allowed_hosts,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn wait_conn_fork(mut sock: libc::c_int) -> libc::c_int {
    let mut sig_action: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut pid: pid_t = 0;
    pid = fork();
    if pid > 0 as libc::c_int {
        close(sock);
        waitpid(pid, 0 as *mut libc::c_int, 0 as libc::c_int);
        return 1 as libc::c_int;
    }
    if pid < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"fork() failed with error %d, bailing out...\0" as *const u8
                as *const libc::c_char,
            *__errno_location(),
        );
        exit(2 as libc::c_int);
    }
    pid = fork();
    if pid < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Second fork() failed with error %d, bailing out...\0" as *const u8
                as *const libc::c_char,
            *__errno_location(),
        );
        exit(2 as libc::c_int);
    }
    if pid > 0 as libc::c_int {
        exit(0 as libc::c_int);
    }
    if sock < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Network server accept failure (%d: %s)\0" as *const u8
                as *const libc::c_char,
            *__errno_location(),
            strerror(*__errno_location()),
        );
        exit(0 as libc::c_int);
    }
    sig_action.__sigaction_handler.sa_sigaction = None;
    sig_action
        .__sigaction_handler
        .sa_handler = Some(child_sighandler as unsafe extern "C" fn(libc::c_int) -> ());
    sigfillset(&mut sig_action.sa_mask);
    sig_action.sa_flags = 0x40000000 as libc::c_int | 0x10000000 as libc::c_int;
    sigaction(3 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    sigaction(15 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    sigaction(1 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    close_listen_socks();
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn conn_check_peer(mut sock: libc::c_int) {
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut nptr: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut nptr6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut ipstr: [libc::c_char; 46] = [0; 46];
    let mut addrlen: socklen_t = 0;
    let mut rc: libc::c_int = 0;
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    rc = getpeername(
        sock,
        &mut addr as *mut sockaddr_storage as *mut sockaddr,
        &mut addrlen,
    );
    if rc < 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Error: Network server getpeername() failure (%d: %s)\0" as *const u8
                as *const libc::c_char,
            *__errno_location(),
            strerror(*__errno_location()),
        );
        close(sock);
        return;
    }
    match addr.ss_family as libc::c_int {
        2 => {
            nptr = &mut addr as *mut sockaddr_storage as *mut sockaddr_in;
            strncpy(
                remote_host.as_mut_ptr(),
                inet_ntoa((*nptr).sin_addr),
                (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            remote_host[(256 as libc::c_int - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        }
        10 => {
            nptr6 = &mut addr as *mut sockaddr_storage as *mut sockaddr_in6;
            if (inet_ntop(
                10 as libc::c_int,
                &mut (*nptr6).sin6_addr as *mut in6_addr as *const libc::c_void,
                ipstr.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 46]>() as libc::c_ulong
                    as socklen_t,
            ))
                .is_null()
            {
                strncpy(
                    ipstr.as_mut_ptr(),
                    b"Unknown\0" as *const u8 as *const libc::c_char,
                    ::core::mem::size_of::<[libc::c_char; 46]>() as libc::c_ulong,
                );
            }
            strncpy(
                remote_host.as_mut_ptr(),
                ipstr.as_mut_ptr(),
                (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            remote_host[(256 as libc::c_int - 1 as libc::c_int)
                as usize] = '\0' as i32 as libc::c_char;
        }
        _ => {}
    }
    if debug == 1 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"CONN_CHECK_PEER: checking if host is allowed: %s port %d\n\0" as *const u8
                as *const libc::c_char,
            remote_host.as_mut_ptr(),
            (*nptr).sin_port as libc::c_int,
        );
    }
    if !allowed_hosts.is_null() {
        match addr.ss_family as libc::c_int {
            2 => {
                if debug == 1 as libc::c_int
                    || sslprm.log_opts as libc::c_uint
                        & SSL_LogIpAddr as libc::c_int as libc::c_uint != 0
                {
                    logit(
                        7 as libc::c_int,
                        b"Connection from %s port %d\0" as *const u8
                            as *const libc::c_char,
                        remote_host.as_mut_ptr(),
                        (*nptr).sin_port as libc::c_int,
                    );
                }
                if is_an_allowed_host(
                    2 as libc::c_int,
                    &mut (*nptr).sin_addr as *mut in_addr as *mut libc::c_void,
                ) == 0
                {
                    logit(
                        3 as libc::c_int,
                        b"Host %s is not allowed to talk to us!\0" as *const u8
                            as *const libc::c_char,
                        remote_host.as_mut_ptr(),
                    );
                    if debug == 1 as libc::c_int {
                        logit(
                            7 as libc::c_int,
                            b"Connection from %s closed.\0" as *const u8
                                as *const libc::c_char,
                            remote_host.as_mut_ptr(),
                        );
                    }
                    close(sock);
                    exit(0 as libc::c_int);
                } else {
                    if debug == 1 as libc::c_int {
                        logit(
                            7 as libc::c_int,
                            b"Host address is in allowed_hosts\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
            }
            10 => {
                strcpy(remote_host.as_mut_ptr(), ipstr.as_mut_ptr());
                if debug == 1 as libc::c_int
                    || sslprm.log_opts as libc::c_uint
                        & SSL_LogIpAddr as libc::c_int as libc::c_uint != 0
                {
                    logit(
                        7 as libc::c_int,
                        b"Connection from %s port %d\0" as *const u8
                            as *const libc::c_char,
                        ipstr.as_mut_ptr(),
                        (*nptr6).sin6_port as libc::c_int,
                    );
                }
                if is_an_allowed_host(
                    10 as libc::c_int,
                    &mut (*nptr6).sin6_addr as *mut in6_addr as *mut libc::c_void,
                ) == 0
                {
                    logit(
                        3 as libc::c_int,
                        b"Host %s is not allowed to talk to us!\0" as *const u8
                            as *const libc::c_char,
                        ipstr.as_mut_ptr(),
                    );
                    if debug == 1 as libc::c_int {
                        logit(
                            7 as libc::c_int,
                            b"Connection from %s closed.\0" as *const u8
                                as *const libc::c_char,
                            ipstr.as_mut_ptr(),
                        );
                    }
                    close(sock);
                    exit(0 as libc::c_int);
                } else {
                    if debug == 1 as libc::c_int {
                        logit(
                            7 as libc::c_int,
                            b"Host address is in allowed_hosts\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn handle_connection(mut sock: libc::c_int) {
    let mut calculated_crc32: u_int32_t = 0;
    let mut temp_command: *mut command = 0 as *mut command;
    let mut receive_packet: v2_packet = v2_packet {
        packet_version: 0,
        packet_type: 0,
        crc32_value: 0,
        result_code: 0,
        buffer: [0; 1024],
    };
    let mut send_packet: v2_packet = v2_packet {
        packet_version: 0,
        packet_type: 0,
        crc32_value: 0,
        result_code: 0,
        buffer: [0; 1024],
    };
    let mut v3_receive_packet: *mut v3_packet = 0 as *mut v3_packet;
    let mut v3_send_packet: *mut v3_packet = 0 as *mut v3_packet;
    let mut bytes_to_send: libc::c_int = 0;
    let mut buffer: [libc::c_char; 2048] = [0; 2048];
    let mut send_buff: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut send_pkt: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut raw_command: [libc::c_char; 2048] = [0; 2048];
    let mut processed_command: [libc::c_char; 2048] = [0; 2048];
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut early_timeout: libc::c_int = 0 as libc::c_int;
    let mut rc: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut pkt_size: int32_t = 0;
    let mut ssl: *mut SSL = 0 as *mut SSL;
    if use_ssl == 1 as libc::c_int {
        ssl = SSL_new(ctx);
        if ssl.is_null() {
            logit(
                3 as libc::c_int,
                b"Error: Could not create SSL connection structure.\0" as *const u8
                    as *const libc::c_char,
            );
            return;
        }
        if handle_conn_ssl(sock, ssl as *mut libc::c_void) != 0 as libc::c_int {
            return;
        }
    }
    rc = read_packet(
        sock,
        ssl as *mut libc::c_void,
        &mut receive_packet,
        &mut v3_receive_packet,
    );
    alarm(0 as libc::c_int as libc::c_uint);
    if rc <= 0 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Could not read request from client %s, bailing out...\0" as *const u8
                as *const libc::c_char,
            remote_host.as_mut_ptr(),
        );
        if !v3_receive_packet.is_null() {
            free(v3_receive_packet as *mut libc::c_void);
        }
        if !ssl.is_null() {
            complete_SSL_shutdown(ssl);
            SSL_free(ssl);
            logit(
                6 as libc::c_int,
                b"INFO: SSL Socket Shutdown.\n\0" as *const u8 as *const libc::c_char,
            );
        }
        return;
    }
    if validate_request(&mut receive_packet, v3_receive_packet) == -(1 as libc::c_int) {
        logit(
            3 as libc::c_int,
            b"Client request from %s was invalid, bailing out...\0" as *const u8
                as *const libc::c_char,
            remote_host.as_mut_ptr(),
        );
        free(command_name as *mut libc::c_void);
        command_name = 0 as *mut libc::c_char;
        x = 0 as libc::c_int;
        while x < 16 as libc::c_int {
            free(macro_argv[x as usize] as *mut libc::c_void);
            macro_argv[x as usize] = 0 as *mut libc::c_char;
            x += 1;
        }
        if !v3_receive_packet.is_null() {
            free(v3_receive_packet as *mut libc::c_void);
        }
        if !ssl.is_null() {
            complete_SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        return;
    }
    if debug == 1 as libc::c_int {
        logit(
            7 as libc::c_int,
            b"Host %s is asking for command '%s' to be run...\0" as *const u8
                as *const libc::c_char,
            remote_host.as_mut_ptr(),
            command_name,
        );
    }
    if strcmp(command_name, b"_NRPE_CHECK\0" as *const u8 as *const libc::c_char) == 0 {
        snprintf(
            buffer.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
            b"NRPE v%s\0" as *const u8 as *const libc::c_char,
            b"4.1.0\0" as *const u8 as *const libc::c_char,
        );
        buffer[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
        if debug == 1 as libc::c_int {
            logit(
                7 as libc::c_int,
                b"Response to %s: %s\0" as *const u8 as *const libc::c_char,
                remote_host.as_mut_ptr(),
                buffer.as_mut_ptr(),
            );
        }
        if !v3_receive_packet.is_null() {
            send_buff = strdup(buffer.as_mut_ptr());
        } else {
            send_buff = calloc(
                1 as libc::c_int as libc::c_ulong,
                ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
            ) as *mut libc::c_char;
            strcpy(send_buff, buffer.as_mut_ptr());
        }
        result = 0 as libc::c_int;
    } else {
        temp_command = find_command(command_name);
        if temp_command.is_null() {
            snprintf(
                buffer.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
                b"NRPE: Command '%s' not defined\0" as *const u8 as *const libc::c_char,
                command_name,
            );
            buffer[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
            if debug == 1 as libc::c_int {
                logit(
                    7 as libc::c_int,
                    b"%s\0" as *const u8 as *const libc::c_char,
                    buffer.as_mut_ptr(),
                );
            }
            if !v3_receive_packet.is_null() {
                send_buff = strdup(buffer.as_mut_ptr());
            } else {
                send_buff = calloc(
                    1 as libc::c_int as libc::c_ulong,
                    ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
                ) as *mut libc::c_char;
                strcpy(send_buff, buffer.as_mut_ptr());
            }
            result = 3 as libc::c_int;
        } else {
            if command_prefix.is_null() {
                strncpy(
                    raw_command.as_mut_ptr(),
                    (*temp_command).command_line,
                    (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
            } else {
                snprintf(
                    raw_command.as_mut_ptr(),
                    (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    b"%s %s\0" as *const u8 as *const libc::c_char,
                    command_prefix,
                    (*temp_command).command_line,
                );
            }
            raw_command[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
            process_macros(
                raw_command.as_mut_ptr(),
                processed_command.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong
                    as libc::c_int,
            );
            if debug == 1 as libc::c_int {
                logit(
                    7 as libc::c_int,
                    b"Running command: %s\0" as *const u8 as *const libc::c_char,
                    processed_command.as_mut_ptr(),
                );
            }
            strcpy(buffer.as_mut_ptr(), b"\0" as *const u8 as *const libc::c_char);
            result = my_system(
                processed_command.as_mut_ptr(),
                command_timeout,
                &mut early_timeout,
                &mut send_buff,
            );
            if debug == 1 as libc::c_int {
                logit(
                    7 as libc::c_int,
                    b"Command completed with return code %d and output: %s\0"
                        as *const u8 as *const libc::c_char,
                    result,
                    send_buff,
                );
            }
            if early_timeout == 1 as libc::c_int {
                sprintf(
                    send_buff,
                    b"NRPE: Command timed out after %d seconds\n\0" as *const u8
                        as *const libc::c_char,
                    command_timeout,
                );
                result = 3 as libc::c_int;
            } else if strcmp(send_buff, b"\0" as *const u8 as *const libc::c_char) == 0 {
                sprintf(
                    send_buff,
                    b"NRPE: Unable to read output\n\0" as *const u8
                        as *const libc::c_char,
                );
                result = 3 as libc::c_int;
            }
            if result < 0 as libc::c_int || result > 3 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Bad return code for [%s]: %d\0" as *const u8
                        as *const libc::c_char,
                    send_buff,
                    result,
                );
                result = 3 as libc::c_int;
            }
        }
    }
    free(command_name as *mut libc::c_void);
    command_name = 0 as *mut libc::c_char;
    x = 0 as libc::c_int;
    while x < 16 as libc::c_int {
        free(macro_argv[x as usize] as *mut libc::c_void);
        macro_argv[x as usize] = 0 as *mut libc::c_char;
        x += 1;
    }
    if !v3_receive_packet.is_null() {
        free(v3_receive_packet as *mut libc::c_void);
    }
    pkt_size = strlen(send_buff) as int32_t;
    if *send_buff
        .offset(
            (strlen(send_buff)).wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
        ) as libc::c_int == '\n' as i32
    {
        *send_buff
            .offset(
                (strlen(send_buff)).wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as isize,
            ) = '\0' as i32 as libc::c_char;
    }
    if packet_ver == 2 as libc::c_int {
        pkt_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong as int32_t;
        send_pkt = &mut send_packet as *mut v2_packet as *mut libc::c_char;
        memset(
            &mut send_packet as *mut v2_packet as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<v2_packet>() as libc::c_ulong,
        );
        randomize_buffer(
            &mut send_packet as *mut v2_packet as *mut libc::c_char,
            ::core::mem::size_of::<v2_packet>() as libc::c_ulong as libc::c_int,
        );
        send_packet.packet_version = __bswap_16(packet_ver as __uint16_t) as int16_t;
        send_packet.packet_type = __bswap_16(2 as libc::c_int as __uint16_t) as int16_t;
        send_packet.result_code = __bswap_16(result as __uint16_t) as int16_t;
        strncpy(
            &mut *(send_packet.buffer).as_mut_ptr().offset(0 as libc::c_int as isize),
            send_buff,
            1024 as libc::c_int as libc::c_ulong,
        );
        send_packet
            .buffer[(1024 as libc::c_int - 1 as libc::c_int)
            as usize] = '\0' as i32 as libc::c_char;
        send_packet.crc32_value = 0 as libc::c_int as u_int32_t;
        calculated_crc32 = calculate_crc32(
            &mut send_packet as *mut v2_packet as *mut libc::c_char,
            ::core::mem::size_of::<v2_packet>() as libc::c_ulong as libc::c_int,
        ) as u_int32_t;
        send_packet.crc32_value = __bswap_32(calculated_crc32);
    } else {
        pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
            .wrapping_sub(4 as libc::c_int as libc::c_ulong)
            .wrapping_add(strlen(send_buff))
            .wrapping_add(1 as libc::c_int as libc::c_ulong) as int32_t;
        if packet_ver == 3 as libc::c_int {
            pkt_size = (::core::mem::size_of::<v3_packet>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_add(strlen(send_buff))
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as int32_t;
        }
        v3_send_packet = calloc(
            1 as libc::c_int as libc::c_ulong,
            pkt_size as libc::c_ulong,
        ) as *mut v3_packet;
        send_pkt = v3_send_packet as *mut libc::c_char;
        (*v3_send_packet)
            .packet_version = __bswap_16(packet_ver as __uint16_t) as int16_t;
        (*v3_send_packet)
            .packet_type = __bswap_16(2 as libc::c_int as __uint16_t) as int16_t;
        (*v3_send_packet).result_code = __bswap_16(result as __uint16_t) as int16_t;
        (*v3_send_packet).alignment = 0 as libc::c_int as int16_t;
        (*v3_send_packet)
            .buffer_length = __bswap_32(
            (strlen(send_buff)).wrapping_add(1 as libc::c_int as libc::c_ulong)
                as __uint32_t,
        ) as int32_t;
        strcpy(
            &mut *((*v3_send_packet).buffer)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize),
            send_buff,
        );
        (*v3_send_packet).crc32_value = 0 as libc::c_int as u_int32_t;
        calculated_crc32 = calculate_crc32(v3_send_packet as *mut libc::c_char, pkt_size)
            as u_int32_t;
        (*v3_send_packet).crc32_value = __bswap_32(calculated_crc32);
    }
    bytes_to_send = pkt_size;
    if use_ssl == 0 as libc::c_int {
        sendall(sock, send_pkt, &mut bytes_to_send);
    } else {
        SSL_write(ssl, send_pkt as *const libc::c_void, bytes_to_send);
    }
    if !ssl.is_null() {
        complete_SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if !v3_send_packet.is_null() {
        free(v3_send_packet as *mut libc::c_void);
    }
    if debug == 1 as libc::c_int {
        logit(
            7 as libc::c_int,
            b"Return Code: %d, Output: %s\0" as *const u8 as *const libc::c_char,
            result,
            send_buff,
        );
    }
    free(send_buff as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn init_handle_conn() {
    let mut sig_action: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    if debug == 1 as libc::c_int {
        logit(
            7 as libc::c_int,
            b"Handling the connection...\0" as *const u8 as *const libc::c_char,
        );
    }
    sig_action.__sigaction_handler.sa_sigaction = None;
    sig_action
        .__sigaction_handler
        .sa_handler = Some(
        my_connection_sighandler as unsafe extern "C" fn(libc::c_int) -> (),
    );
    sigfillset(&mut sig_action.sa_mask);
    sig_action.sa_flags = 0x40000000 as libc::c_int | 0x10000000 as libc::c_int;
    sigaction(14 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
    alarm(connection_timeout as libc::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn handle_conn_ssl(
    mut sock: libc::c_int,
    mut ssl_ptr: *mut libc::c_void,
) -> libc::c_int {
    let mut c: *const SSL_CIPHER = 0 as *const SSL_CIPHER;
    let mut errmsg: *const libc::c_char = 0 as *const libc::c_char;
    let mut buffer: [libc::c_char; 2048] = [0; 2048];
    let mut ssl: *mut SSL = ssl_ptr as *mut SSL;
    let mut peer: *mut X509 = 0 as *mut X509;
    let mut rc: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut sockfd: libc::c_int = 0;
    let mut retval: libc::c_int = 0;
    let mut rfds: fd_set = fd_set { __fds_bits: [0; 16] };
    let mut timeout: timeval = timeval { tv_sec: 0, tv_usec: 0 };
    SSL_set_fd(ssl, sock);
    sockfd = SSL_get_fd(ssl);
    let mut __d0: libc::c_int = 0;
    let mut __d1: libc::c_int = 0;
    let fresh0 = &mut __d0;
    let fresh1;
    let fresh2 = (::core::mem::size_of::<fd_set>() as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<__fd_mask>() as libc::c_ulong);
    let fresh3 = &mut __d1;
    let fresh4;
    let fresh5 = &mut *(rfds.__fds_bits).as_mut_ptr().offset(0 as libc::c_int as isize)
        as *mut __fd_mask;
    asm!(
        "cld; rep; stosq", inlateout("cx") c2rust_asm_casts::AsmCast::cast_in(fresh0,
        fresh2) => fresh1, inlateout("di") c2rust_asm_casts::AsmCast::cast_in(fresh3,
        fresh5) => fresh4, inlateout("ax") 0 as libc::c_int => _,
        options(preserves_flags, att_syntax)
    );
    c2rust_asm_casts::AsmCast::cast_out(fresh0, fresh2, fresh1);
    c2rust_asm_casts::AsmCast::cast_out(fresh3, fresh5, fresh4);
    rfds
        .__fds_bits[(sockfd
        / (8 as libc::c_int
            * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong as libc::c_int))
        as usize]
        |= ((1 as libc::c_ulong)
            << sockfd
                % (8 as libc::c_int
                    * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                        as libc::c_int)) as __fd_mask;
    timeout.tv_sec = connection_timeout as __time_t;
    timeout.tv_usec = 0 as libc::c_int as __suseconds_t;
    loop {
        retval = select(
            sockfd + 1 as libc::c_int,
            &mut rfds,
            0 as *mut fd_set,
            0 as *mut fd_set,
            &mut timeout,
        );
        if retval > 0 as libc::c_int {
            rc = SSL_accept(ssl);
        } else {
            logit(
                3 as libc::c_int,
                b"Error: (!log_opts) Could not complete SSL handshake with %s: timeout %d seconds\0"
                    as *const u8 as *const libc::c_char,
                remote_host.as_mut_ptr(),
                connection_timeout,
            );
            return -(1 as libc::c_int);
        }
        if !(SSL_get_error(ssl, rc) == 2 as libc::c_int) {
            break;
        }
    }
    if rc != 1 as libc::c_int {
        if sslprm.log_opts as libc::c_uint
            & (SSL_LogCertDetails as libc::c_int | SSL_LogIfClientCert as libc::c_int)
                as libc::c_uint != 0
        {
            let mut nerrs: libc::c_int = 0 as libc::c_int;
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
                errmsg = ERR_reason_error_string(x as libc::c_ulong);
                logit(
                    3 as libc::c_int,
                    b"Error: (ERR_get_error_line_data = %d), Could not complete SSL handshake with %s: %s\0"
                        as *const u8 as *const libc::c_char,
                    x,
                    remote_host.as_mut_ptr(),
                    errmsg,
                );
                if !errmsg.is_null()
                    && strcmp(
                        errmsg,
                        b"no shared cipher\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    && ((sslprm.cert_file).is_null() || (sslprm.cacert_file).is_null())
                {
                    logit(
                        3 as libc::c_int,
                        b"Error: This could be because you have not specified certificate or ca-certificate files\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
                nerrs += 1;
            }
            if nerrs == 0 as libc::c_int {
                logit(
                    3 as libc::c_int,
                    b"Error: (nerrs = 0) Could not complete SSL handshake with %s: %d\0"
                        as *const u8 as *const libc::c_char,
                    remote_host.as_mut_ptr(),
                    SSL_get_error(ssl, rc),
                );
            }
        } else {
            logit(
                3 as libc::c_int,
                b"Error: (!log_opts) Could not complete SSL handshake with %s: %d\0"
                    as *const u8 as *const libc::c_char,
                remote_host.as_mut_ptr(),
                SSL_get_error(ssl, rc),
            );
        }
        return -(1 as libc::c_int);
    }
    if sslprm.log_opts as libc::c_uint & SSL_LogVersion as libc::c_int as libc::c_uint
        != 0
    {
        logit(
            5 as libc::c_int,
            b"Remote %s - SSL Version: %s\0" as *const u8 as *const libc::c_char,
            remote_host.as_mut_ptr(),
            SSL_get_version(ssl),
        );
    }
    if sslprm.log_opts as libc::c_uint & SSL_LogCipher as libc::c_int as libc::c_uint
        != 0
    {
        c = SSL_get_current_cipher(ssl);
        logit(
            5 as libc::c_int,
            b"Remote %s - %s, Cipher is %s\0" as *const u8 as *const libc::c_char,
            remote_host.as_mut_ptr(),
            SSL_CIPHER_get_version(c),
            SSL_CIPHER_get_name(c),
        );
    }
    if sslprm.log_opts as libc::c_uint
        & SSL_LogIfClientCert as libc::c_int as libc::c_uint != 0
        || sslprm.log_opts as libc::c_uint
            & SSL_LogCertDetails as libc::c_int as libc::c_uint != 0
    {
        peer = SSL_get_peer_certificate(ssl);
        if !peer.is_null() {
            if sslprm.log_opts as libc::c_uint
                & SSL_LogIfClientCert as libc::c_int as libc::c_uint != 0
            {
                logit(
                    5 as libc::c_int,
                    b"SSL Client %s has %s certificate\0" as *const u8
                        as *const libc::c_char,
                    remote_host.as_mut_ptr(),
                    if SSL_get_verify_result(ssl) == 0 as libc::c_int as libc::c_long {
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
                    b"SSL Client %s Cert Name: %s\0" as *const u8 as *const libc::c_char,
                    remote_host.as_mut_ptr(),
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
                    b"SSL Client %s Cert Issuer: %s\0" as *const u8
                        as *const libc::c_char,
                    remote_host.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                );
            }
        } else if sslprm.client_certs as libc::c_uint == 0 as libc::c_int as libc::c_uint
        {
            logit(
                5 as libc::c_int,
                b"SSL Not asking for client certification\0" as *const u8
                    as *const libc::c_char,
            );
        } else {
            logit(
                5 as libc::c_int,
                b"SSL Client %s did not present a certificate\0" as *const u8
                    as *const libc::c_char,
                remote_host.as_mut_ptr(),
            );
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn read_packet(
    mut sock: libc::c_int,
    mut ssl_ptr: *mut libc::c_void,
    mut v2_pkt: *mut v2_packet,
    mut v3_pkt: *mut *mut v3_packet,
) -> libc::c_int {
    let mut common_size: int32_t = 0;
    let mut tot_bytes: int32_t = 0;
    let mut bytes_to_recv: int32_t = 0;
    let mut buffer_size: int32_t = 0;
    let mut rc: libc::c_int = 0;
    let mut buff_ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    bytes_to_recv = (&mut (*v2_pkt).buffer as *mut [libc::c_char; 1024]
        as *mut libc::c_char)
        .offset_from(v2_pkt as *mut libc::c_char) as libc::c_long as int32_t;
    tot_bytes = bytes_to_recv;
    common_size = tot_bytes;
    if use_ssl == 0 as libc::c_int {
        rc = recvall(sock, v2_pkt as *mut libc::c_char, &mut tot_bytes, socket_timeout);
        if rc <= 0 as libc::c_int || rc != bytes_to_recv {
            return -(1 as libc::c_int);
        }
        packet_ver = __bswap_16((*v2_pkt).packet_version as __uint16_t) as libc::c_int;
        if packet_ver != 2 as libc::c_int && packet_ver != 4 as libc::c_int {
            logit(
                3 as libc::c_int,
                b"Error: (use_ssl == false): Request packet version was invalid!\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if packet_ver == 2 as libc::c_int {
            buffer_size = (::core::mem::size_of::<v2_packet>() as libc::c_ulong)
                .wrapping_sub(common_size as libc::c_ulong) as int32_t;
            buff_ptr = (v2_pkt as *mut libc::c_char).offset(common_size as isize);
        } else {
            let mut pkt_size: int32_t = (::core::mem::size_of::<v3_packet>()
                as libc::c_ulong)
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
                    b"Error: (use_ssl == false): Received packet with invalid buffer size\0"
                        as *const u8 as *const libc::c_char,
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
                    b"Error: (use_ssl == false): Could not allocate memory for packet\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v3_pkt as *mut libc::c_void,
                v2_pkt as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            (**v3_pkt).buffer_length = __bswap_32(buffer_size as __uint32_t) as int32_t;
            buff_ptr = ((**v3_pkt).buffer).as_mut_ptr();
        }
        bytes_to_recv = buffer_size;
        rc = recvall(sock, buff_ptr, &mut bytes_to_recv, socket_timeout);
        if rc <= 0 as libc::c_int || rc != buffer_size {
            if packet_ver == 3 as libc::c_int {
                free(*v3_pkt as *mut libc::c_void);
                *v3_pkt = 0 as *mut v3_packet;
            }
            return -(1 as libc::c_int);
        } else {
            tot_bytes += rc;
        }
    } else {
        let mut ssl: *mut SSL = ssl_ptr as *mut SSL;
        let mut sockfd: libc::c_int = 0;
        let mut retval: libc::c_int = 0;
        let mut rfds: fd_set = fd_set { __fds_bits: [0; 16] };
        let mut timeout: timeval = timeval { tv_sec: 0, tv_usec: 0 };
        sockfd = SSL_get_fd(ssl);
        let mut __d0: libc::c_int = 0;
        let mut __d1: libc::c_int = 0;
        let fresh6 = &mut __d0;
        let fresh7;
        let fresh8 = (::core::mem::size_of::<fd_set>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<__fd_mask>() as libc::c_ulong);
        let fresh9 = &mut __d1;
        let fresh10;
        let fresh11 = &mut *(rfds.__fds_bits)
            .as_mut_ptr()
            .offset(0 as libc::c_int as isize) as *mut __fd_mask;
        asm!(
            "cld; rep; stosq", inlateout("cx") c2rust_asm_casts::AsmCast::cast_in(fresh6,
            fresh8) => fresh7, inlateout("di") c2rust_asm_casts::AsmCast::cast_in(fresh9,
            fresh11) => fresh10, inlateout("ax") 0 as libc::c_int => _,
            options(preserves_flags, att_syntax)
        );
        c2rust_asm_casts::AsmCast::cast_out(fresh6, fresh8, fresh7);
        c2rust_asm_casts::AsmCast::cast_out(fresh9, fresh11, fresh10);
        rfds
            .__fds_bits[(sockfd
            / (8 as libc::c_int
                * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong as libc::c_int))
            as usize]
            |= ((1 as libc::c_ulong)
                << sockfd
                    % (8 as libc::c_int
                        * ::core::mem::size_of::<__fd_mask>() as libc::c_ulong
                            as libc::c_int)) as __fd_mask;
        timeout.tv_sec = connection_timeout as __time_t;
        timeout.tv_usec = 0 as libc::c_int as __suseconds_t;
        loop {
            retval = select(
                sockfd + 1 as libc::c_int,
                &mut rfds,
                0 as *mut fd_set,
                0 as *mut fd_set,
                &mut timeout,
            );
            if retval > 0 as libc::c_int {
                rc = SSL_read(ssl, v2_pkt as *mut libc::c_void, bytes_to_recv);
            } else {
                logit(
                    3 as libc::c_int,
                    b"Error (!log_opts): Could not complete SSL_read with %s: timeout %d seconds\0"
                        as *const u8 as *const libc::c_char,
                    remote_host.as_mut_ptr(),
                    connection_timeout,
                );
                return -(1 as libc::c_int);
            }
            if !(SSL_get_error(ssl, rc) == 2 as libc::c_int) {
                break;
            }
        }
        if rc <= 0 as libc::c_int || rc != bytes_to_recv {
            return -(1 as libc::c_int);
        }
        packet_ver = __bswap_16((*v2_pkt).packet_version as __uint16_t) as libc::c_int;
        if packet_ver != 2 as libc::c_int && packet_ver != 4 as libc::c_int {
            logit(
                3 as libc::c_int,
                b"Error: (use_ssl == true): Request packet version was invalid!\0"
                    as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if packet_ver == 2 as libc::c_int {
            buffer_size = (::core::mem::size_of::<v2_packet>() as libc::c_ulong)
                .wrapping_sub(common_size as libc::c_ulong) as int32_t;
            buff_ptr = (v2_pkt as *mut libc::c_char).offset(common_size as isize);
        } else {
            let mut pkt_size_0: int32_t = ::core::mem::size_of::<v3_packet>()
                as libc::c_ulong as int32_t;
            if packet_ver == 3 as libc::c_int {
                pkt_size_0 -= 1 as libc::c_int;
            } else if packet_ver == 4 as libc::c_int {
                pkt_size_0 -= 4 as libc::c_int;
            }
            bytes_to_recv = ::core::mem::size_of::<int16_t>() as libc::c_ulong
                as int32_t;
            loop {
                rc = SSL_read(
                    ssl,
                    &mut buffer_size as *mut int32_t as *mut libc::c_void,
                    bytes_to_recv,
                );
                if !(rc <= 0 as libc::c_int
                    && SSL_get_error(ssl, rc) == 2 as libc::c_int)
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
                    ssl,
                    &mut buffer_size as *mut int32_t as *mut libc::c_void,
                    bytes_to_recv,
                );
                if !(rc <= 0 as libc::c_int
                    && SSL_get_error(ssl, rc) == 2 as libc::c_int)
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
                    b"Error: (use_ssl == true): Received packet with invalid buffer size\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            pkt_size_0 += buffer_size;
            *v3_pkt = calloc(
                1 as libc::c_int as libc::c_ulong,
                pkt_size_0 as libc::c_ulong,
            ) as *mut v3_packet;
            if (*v3_pkt).is_null() {
                logit(
                    3 as libc::c_int,
                    b"Error: (use_ssl == true): Could not allocate memory for packet\0"
                        as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            memcpy(
                *v3_pkt as *mut libc::c_void,
                v2_pkt as *const libc::c_void,
                common_size as libc::c_ulong,
            );
            (**v3_pkt).buffer_length = __bswap_32(buffer_size as __uint32_t) as int32_t;
            buff_ptr = ((**v3_pkt).buffer).as_mut_ptr();
        }
        bytes_to_recv = buffer_size;
        loop {
            rc = SSL_read(ssl, buff_ptr as *mut libc::c_void, bytes_to_recv);
            if !(rc <= 0 as libc::c_int && SSL_get_error(ssl, rc) == 2 as libc::c_int) {
                break;
            }
        }
        if rc <= 0 as libc::c_int || rc != buffer_size {
            if packet_ver == 3 as libc::c_int {
                free(*v3_pkt as *mut libc::c_void);
                *v3_pkt = 0 as *mut v3_packet;
            }
            return -(1 as libc::c_int);
        } else {
            tot_bytes += rc;
        }
    }
    return tot_bytes;
}
#[no_mangle]
pub unsafe extern "C" fn free_memory() {
    let mut this_command: *mut command = 0 as *mut command;
    let mut next_command: *mut command = 0 as *mut command;
    this_command = command_list;
    while !this_command.is_null() {
        next_command = (*this_command).next;
        if !((*this_command).command_name).is_null() {
            free((*this_command).command_name as *mut libc::c_void);
        }
        if !((*this_command).command_line).is_null() {
            free((*this_command).command_line as *mut libc::c_void);
        }
        free(this_command as *mut libc::c_void);
        this_command = next_command;
    }
    command_list = 0 as *mut command;
}
#[no_mangle]
pub unsafe extern "C" fn my_system(
    mut command: *mut libc::c_char,
    mut timeout: libc::c_int,
    mut early_timeout: *mut libc::c_int,
    mut output: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut pid: pid_t = 0;
    let mut start_time: time_t = 0;
    let mut end_time: time_t = 0;
    let mut status: libc::c_int = 0;
    let mut result: libc::c_int = 0;
    let mut buffer: [libc::c_char; 2048] = [0; 2048];
    let mut fd: [libc::c_int; 2] = [0; 2];
    let mut bytes_read: libc::c_int = 0 as libc::c_int;
    let mut tot_bytes: libc::c_int = 0 as libc::c_int;
    let mut output_size: libc::c_int = 0;
    let mut sig_action: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    *early_timeout = 0 as libc::c_int;
    if command.is_null() {
        return 0 as libc::c_int;
    }
    if max_commands != 0 as libc::c_int {
        while commands_running >= max_commands {
            logit(
                4 as libc::c_int,
                b"Commands choked. Sleeping 1s - commands_running: %d, max_commands: %d\0"
                    as *const u8 as *const libc::c_char,
                commands_running,
                max_commands,
            );
            sleep(1 as libc::c_int as libc::c_uint);
        }
    }
    if pipe(fd.as_mut_ptr()) == -(1 as libc::c_int) {
        logit(
            3 as libc::c_int,
            b"ERROR: pipe(): %s, bailing out...\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        exit(2 as libc::c_int);
    }
    fcntl(fd[0 as libc::c_int as usize], 4 as libc::c_int, 0o4000 as libc::c_int);
    fcntl(fd[1 as libc::c_int as usize], 4 as libc::c_int, 0o4000 as libc::c_int);
    time(&mut start_time);
    pid = fork();
    if pid == -(1 as libc::c_int) {
        snprintf(
            buffer.as_mut_ptr(),
            (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            b"NRPE: Call to fork() failed\n\0" as *const u8 as *const libc::c_char,
        );
        buffer[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            as usize] = '\0' as i32 as libc::c_char;
        if packet_ver == 2 as libc::c_int {
            let mut output_size_0: libc::c_int = ::core::mem::size_of::<v2_packet>()
                as libc::c_ulong as libc::c_int;
            *output = calloc(
                1 as libc::c_int as libc::c_ulong,
                output_size_0 as libc::c_ulong,
            ) as *mut libc::c_char;
            strncpy(
                *output,
                buffer.as_mut_ptr(),
                (output_size_0 - 1 as libc::c_int) as libc::c_ulong,
            );
            **output
                .offset(
                    (output_size_0 - 1 as libc::c_int) as isize,
                ) = '\0' as i32 as libc::c_char;
        } else {
            *output = strdup(buffer.as_mut_ptr());
        }
        close(fd[0 as libc::c_int as usize]);
        close(fd[1 as libc::c_int as usize]);
        return 3 as libc::c_int;
    }
    if pid == 0 as libc::c_int {
        if seteuid(0 as libc::c_int as __uid_t) == -(1 as libc::c_int) && debug != 0 {
            logit(
                4 as libc::c_int,
                b"WARNING: my_system() seteuid(0): %s\0" as *const u8
                    as *const libc::c_char,
                strerror(*__errno_location()),
            );
        }
        drop_privileges(nrpe_user, nrpe_group, 1 as libc::c_int);
        close(fd[0 as libc::c_int as usize]);
        setpgid(0 as libc::c_int, 0 as libc::c_int);
        sig_action.__sigaction_handler.sa_sigaction = None;
        sig_action
            .__sigaction_handler
            .sa_handler = Some(
            my_system_sighandler as unsafe extern "C" fn(libc::c_int) -> (),
        );
        sigfillset(&mut sig_action.sa_mask);
        sig_action.sa_flags = 0x40000000 as libc::c_int | 0x10000000 as libc::c_int;
        sigaction(14 as libc::c_int, &mut sig_action, 0 as *mut sigaction);
        alarm(timeout as libc::c_uint);
        fp = popen(command, b"r\0" as *const u8 as *const libc::c_char);
        if fp.is_null() {
            strncpy(
                buffer.as_mut_ptr(),
                b"NRPE: Call to popen() failed\n\0" as *const u8 as *const libc::c_char,
                (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            buffer[(::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                as usize] = '\0' as i32 as libc::c_char;
            if write(
                fd[1 as libc::c_int as usize],
                buffer.as_mut_ptr() as *const libc::c_void,
                (strlen(buffer.as_mut_ptr()))
                    .wrapping_add(1 as libc::c_int as libc::c_ulong),
            ) == -(1 as libc::c_int) as libc::c_long
            {
                logit(
                    3 as libc::c_int,
                    b"ERROR: my_system() write(fd, buffer)-1 failed...\0" as *const u8
                        as *const libc::c_char,
                );
            }
            result = 2 as libc::c_int;
        } else {
            loop {
                bytes_read = fread(
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    1 as libc::c_int as libc::c_ulong,
                    (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    fp,
                ) as libc::c_int;
                if !(bytes_read > 0 as libc::c_int) {
                    break;
                }
                if write(
                    fd[1 as libc::c_int as usize],
                    buffer.as_mut_ptr() as *const libc::c_void,
                    bytes_read as size_t,
                ) == -(1 as libc::c_int) as libc::c_long
                {
                    logit(
                        3 as libc::c_int,
                        b"ERROR: my_system() write(fd, buffer)-2 failed...\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
            }
            if write(
                fd[1 as libc::c_int as usize],
                b"\0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                1 as libc::c_int as size_t,
            ) == -(1 as libc::c_int) as libc::c_long
            {
                logit(
                    3 as libc::c_int,
                    b"ERROR: my_system() write(fd, NULL) failed...\0" as *const u8
                        as *const libc::c_char,
                );
            }
            status = pclose(fp);
            if status == -(1 as libc::c_int) {
                result = 2 as libc::c_int;
            } else if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
                result = 2 as libc::c_int;
            } else {
                result = (status & 0xff00 as libc::c_int) >> 8 as libc::c_int;
            }
        }
        close(fd[1 as libc::c_int as usize]);
        alarm(0 as libc::c_int as libc::c_uint);
        exit(result);
    } else {
        commands_running += 1;
        close(fd[1 as libc::c_int as usize]);
        waitpid(pid, &mut status, 0 as libc::c_int);
        time(&mut end_time);
        result = (status & 0xff00 as libc::c_int) >> 8 as libc::c_int;
        if result == 255 as libc::c_int {
            result = 3 as libc::c_int;
        }
        if result < 0 as libc::c_int || result > 3 as libc::c_int {
            result = 3 as libc::c_int;
        }
        if packet_ver == 2 as libc::c_int {
            output_size = ::core::mem::size_of::<v2_packet>() as libc::c_ulong
                as libc::c_int;
            *output = calloc(
                1 as libc::c_int as libc::c_ulong,
                output_size as libc::c_ulong,
            ) as *mut libc::c_char;
        } else {
            output_size = 1024 as libc::c_int * 64 as libc::c_int;
            *output = calloc(
                1 as libc::c_int as libc::c_ulong,
                output_size as libc::c_ulong,
            ) as *mut libc::c_char;
        }
        loop {
            bytes_read = read(
                fd[0 as libc::c_int as usize],
                buffer.as_mut_ptr() as *mut libc::c_void,
                (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ) as libc::c_int;
            if bytes_read == 0 as libc::c_int {
                break;
            }
            if bytes_read == -(1 as libc::c_int) {
                if !(*__errno_location() == 4 as libc::c_int) {
                    break;
                }
            } else {
                if tot_bytes < output_size {
                    strncat(
                        *output,
                        buffer.as_mut_ptr(),
                        (output_size - tot_bytes - 1 as libc::c_int) as libc::c_ulong,
                    );
                }
                tot_bytes += bytes_read;
            }
        }
        *(*output)
            .offset(
                (output_size - 1 as libc::c_int) as isize,
            ) = '\0' as i32 as libc::c_char;
        if result == 2 as libc::c_int && bytes_read == -(1 as libc::c_int)
            && end_time - start_time >= timeout as libc::c_long
        {
            *early_timeout = 1 as libc::c_int;
            kill(-pid, 15 as libc::c_int);
            kill(-pid, 9 as libc::c_int);
        }
        close(fd[0 as libc::c_int as usize]);
        commands_running -= 1;
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn my_system_sighandler(mut sig: libc::c_int) {
    exit(2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn my_connection_sighandler(mut sig: libc::c_int) {
    logit(
        3 as libc::c_int,
        b"Connection has taken too long to establish. Exiting...\0" as *const u8
            as *const libc::c_char,
    );
    exit(2 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn drop_privileges(
    mut user: *mut libc::c_char,
    mut group: *mut libc::c_char,
    mut full_drop: libc::c_int,
) -> libc::c_int {
    let mut uid: uid_t = -(1 as libc::c_int) as uid_t;
    let mut gid: gid_t = -(1 as libc::c_int) as gid_t;
    let mut grp: *mut group = 0 as *mut group;
    let mut pw: *mut passwd = 0 as *mut passwd;
    if use_inetd == 1 as libc::c_int {
        return 0 as libc::c_int;
    }
    if !group.is_null() {
        if strspn(group, b"0123456789\0" as *const u8 as *const libc::c_char)
            < strlen(group)
        {
            grp = getgrnam(group);
            if !grp.is_null() {
                gid = (*grp).gr_gid;
            } else {
                logit(
                    3 as libc::c_int,
                    b"Warning: Could not get group entry for '%s'\0" as *const u8
                        as *const libc::c_char,
                    group,
                );
            }
            endgrent();
        } else {
            gid = atoi(group) as gid_t;
        }
        if gid != getegid() {
            if setgid(gid) == -(1 as libc::c_int) {
                logit(
                    3 as libc::c_int,
                    b"Warning: Could not set effective GID=%d\0" as *const u8
                        as *const libc::c_char,
                    gid as libc::c_int,
                );
            }
        }
    }
    if !user.is_null() {
        if strspn(user, b"0123456789\0" as *const u8 as *const libc::c_char)
            < strlen(user)
        {
            pw = getpwnam(user);
            if !pw.is_null() {
                uid = (*pw).pw_uid;
            } else {
                logit(
                    3 as libc::c_int,
                    b"Warning: Could not get passwd entry for '%s'\0" as *const u8
                        as *const libc::c_char,
                    user,
                );
            }
            endpwent();
        } else {
            uid = atoi(user) as uid_t;
        }
        if uid != geteuid() {
            if initgroups(user, gid) == -(1 as libc::c_int) {
                if *__errno_location() == 1 as libc::c_int {
                    logit(
                        3 as libc::c_int,
                        b"Warning: Unable to change supplementary groups using initgroups()\0"
                            as *const u8 as *const libc::c_char,
                    );
                } else {
                    logit(
                        3 as libc::c_int,
                        b"Warning: Possibly root user failed dropping privileges with initgroups()\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                }
            }
            if full_drop != 0 {
                if setuid(uid) == -(1 as libc::c_int) {
                    logit(
                        3 as libc::c_int,
                        b"Warning: Could not set UID=%d\0" as *const u8
                            as *const libc::c_char,
                        uid as libc::c_int,
                    );
                }
            } else if seteuid(uid) == -(1 as libc::c_int) {
                logit(
                    3 as libc::c_int,
                    b"Warning: Could not set effective UID=%d\0" as *const u8
                        as *const libc::c_char,
                    uid as libc::c_int,
                );
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn write_pid_file() -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut result: libc::c_int = 0 as libc::c_int;
    let mut pid: pid_t = 0 as libc::c_int;
    let mut pbuf: [libc::c_char; 16] = [0; 16];
    if pid_file.is_null() {
        return 0 as libc::c_int;
    }
    fd = open(pid_file, 0 as libc::c_int);
    if fd >= 0 as libc::c_int {
        result = read(
            fd,
            pbuf.as_mut_ptr() as *mut libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) as libc::c_int;
        close(fd);
        if result > 0 as libc::c_int {
            pbuf[result as usize] = '\0' as i32 as libc::c_char;
            pid = atoi(pbuf.as_mut_ptr());
            if pid != 0
                && (pid == getpid() || kill(pid, 0 as libc::c_int) < 0 as libc::c_int)
            {
                unlink(pid_file);
            } else {
                logit(
                    3 as libc::c_int,
                    b"There's already an NRPE server running (PID %lu).  Bailing out...\0"
                        as *const u8 as *const libc::c_char,
                    pid as libc::c_ulong,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    fd = open(pid_file, 0o1 as libc::c_int | 0o100 as libc::c_int, 0o644 as libc::c_int);
    if fd >= 0 as libc::c_int {
        sprintf(
            pbuf.as_mut_ptr(),
            b"%d\n\0" as *const u8 as *const libc::c_char,
            getpid(),
        );
        if write(fd, pbuf.as_mut_ptr() as *const libc::c_void, strlen(pbuf.as_mut_ptr()))
            == -(1 as libc::c_int) as libc::c_long
        {
            logit(
                3 as libc::c_int,
                b"ERROR: write_pid_file() write(fd, pbuf) failed...\0" as *const u8
                    as *const libc::c_char,
            );
        }
        close(fd);
        wrote_pid_file = 1 as libc::c_int;
    } else {
        logit(
            3 as libc::c_int,
            b"Cannot write to pidfile '%s' - check your privileges.\0" as *const u8
                as *const libc::c_char,
            pid_file,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn remove_pid_file() -> libc::c_int {
    if pid_file.is_null() {
        return 0 as libc::c_int;
    }
    if wrote_pid_file == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if seteuid(0 as libc::c_int as __uid_t) == -(1 as libc::c_int) && debug != 0 {
        logit(
            4 as libc::c_int,
            b"WARNING: remove_pid_file() seteuid(0): %s\0" as *const u8
                as *const libc::c_char,
            strerror(*__errno_location()),
        );
    }
    if unlink(pid_file) == -(1 as libc::c_int) {
        logit(
            3 as libc::c_int,
            b"Cannot remove pidfile '%s' - check your privileges.\0" as *const u8
                as *const libc::c_char,
            pid_file,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn my_disconnect_sighandler(mut sig: libc::c_int) {
    logit(
        3 as libc::c_int,
        b"SSL_shutdown() has taken too long to complete. Exiting now..\0" as *const u8
            as *const libc::c_char,
    );
    exit(2 as libc::c_int);
}
unsafe extern "C" fn complete_SSL_shutdown(mut ssl: *mut SSL) {
    let mut x: libc::c_int = 0;
    signal(
        14 as libc::c_int,
        Some(my_disconnect_sighandler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    alarm(ssl_shutdown_timeout as libc::c_uint);
    x = 0 as libc::c_int;
    while x < 4 as libc::c_int {
        if SSL_shutdown(ssl) != 0 {
            break;
        }
        x += 1;
    }
    alarm(0 as libc::c_int as libc::c_uint);
}
#[no_mangle]
pub unsafe extern "C" fn check_privileges() -> libc::c_int {
    let mut uid: uid_t = geteuid();
    let mut gid: gid_t = getegid();
    if uid == 0 as libc::c_int as libc::c_uint || gid == 0 as libc::c_int as libc::c_uint
    {
        logit(
            3 as libc::c_int,
            b"Error: NRPE daemon cannot be run as user/group root!\0" as *const u8
                as *const libc::c_char,
        );
        exit(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sighandler(mut sig: libc::c_int) {
    static mut sigs: [*mut libc::c_char; 35] = [
        b"EXIT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"HUP\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"INT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"QUIT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ILL\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"TRAP\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ABRT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"BUS\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"FPE\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"KILL\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"USR1\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"SEGV\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"USR2\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"PIPE\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ALRM\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"TERM\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"STKFLT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"CHLD\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"CONT\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"STOP\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"TSTP\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"TTIN\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"TTOU\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"URG\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"XCPU\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"XFSZ\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"VTALRM\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"PROF\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"WINCH\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"IO\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"PWR\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"UNUSED\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"ZERR\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"DEBUG\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        0 as *const libc::c_void as *mut libc::c_void as *mut libc::c_char,
    ];
    let mut i: libc::c_int = 0;
    if sig < 0 as libc::c_int {
        sig = -sig;
    }
    i = 0 as libc::c_int;
    while !(sigs[i as usize]).is_null() {
        i += 1;
    }
    sig %= i;
    if sig == 1 as libc::c_int {
        sigrestart = 1 as libc::c_int;
        logit(
            5 as libc::c_int,
            b"Caught SIGHUP - restarting...\n\0" as *const u8 as *const libc::c_char,
        );
    }
    if sig == 15 as libc::c_int {
        if sigshutdown == 1 as libc::c_int {
            exit(2 as libc::c_int);
        }
        sigshutdown = 1 as libc::c_int;
        logit(
            5 as libc::c_int,
            b"Caught SIG%s - shutting down...\n\0" as *const u8 as *const libc::c_char,
            sigs[sig as usize],
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn child_sighandler(mut sig: libc::c_int) {
    exit(0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn validate_request(
    mut v2pkt: *mut v2_packet,
    mut v3pkt: *mut v3_packet,
) -> libc::c_int {
    let mut packet_crc32: u_int32_t = 0;
    let mut calculated_crc32: u_int32_t = 0;
    let mut pkt_size: int32_t = 0;
    let mut buffer_size: int32_t = 0;
    let mut buff: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    if packet_ver >= 3 as libc::c_int {
        buffer_size = __bswap_32((*v3pkt).buffer_length as __uint32_t) as int32_t;
        pkt_size = ::core::mem::size_of::<v3_packet>() as libc::c_ulong as int32_t;
        pkt_size
            -= if packet_ver == 3 as libc::c_int {
                1 as libc::c_int
            } else {
                4 as libc::c_int
            };
        pkt_size += buffer_size;
        packet_crc32 = __bswap_32((*v3pkt).crc32_value);
        (*v3pkt).crc32_value = 0 as libc::c_long as u_int32_t;
        (*v3pkt).alignment = 0 as libc::c_int as int16_t;
        calculated_crc32 = calculate_crc32(v3pkt as *mut libc::c_char, pkt_size)
            as u_int32_t;
    } else {
        packet_crc32 = __bswap_32((*v2pkt).crc32_value);
        (*v2pkt).crc32_value = 0 as libc::c_long as u_int32_t;
        calculated_crc32 = calculate_crc32(
            v2pkt as *mut libc::c_char,
            ::core::mem::size_of::<v2_packet>() as libc::c_ulong as libc::c_int,
        ) as u_int32_t;
    }
    if packet_crc32 != calculated_crc32 {
        logit(
            3 as libc::c_int,
            b"Error: Request packet had invalid CRC32.\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if __bswap_16((*v2pkt).packet_type as __uint16_t) as libc::c_int != 1 as libc::c_int
    {
        logit(
            3 as libc::c_int,
            b"Error: Request packet type was invalid!\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if packet_ver >= 3 as libc::c_int {
        let mut l: int32_t = __bswap_16((*v3pkt).buffer_length as __uint16_t) as int32_t;
        *((*v3pkt).buffer)
            .as_mut_ptr()
            .offset((l - 1 as libc::c_int) as isize) = '\0' as i32 as libc::c_char;
        buff = ((*v3pkt).buffer).as_mut_ptr();
    } else {
        (*v2pkt)
            .buffer[(1024 as libc::c_int - 1 as libc::c_int)
            as usize] = '\0' as i32 as libc::c_char;
        buff = ((*v2pkt).buffer).as_mut_ptr();
    }
    if *buff.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
        logit(
            3 as libc::c_int,
            b"Error: Request contained no query!\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if packet_ver >= 3 as libc::c_int {
        rc = contains_nasty_metachars(((*v3pkt).buffer).as_mut_ptr());
    } else {
        rc = contains_nasty_metachars(((*v2pkt).buffer).as_mut_ptr());
    }
    if rc == 1 as libc::c_int {
        logit(
            3 as libc::c_int,
            b"Error: Request contained illegal metachars!\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if !(strchr(buff, '!' as i32)).is_null() {
        logit(
            3 as libc::c_int,
            b"Error: Request contained command arguments!\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    ptr = buff;
    command_name = strdup(ptr);
    if command_name.is_null() {
        logit(
            3 as libc::c_int,
            b"Error: Memory allocation failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn contains_nasty_metachars(
    mut str: *mut libc::c_char,
) -> libc::c_int {
    let mut result: libc::c_int = 0;
    if str.is_null() {
        return 0 as libc::c_int;
    }
    result = strcspn(str, nasty_metachars) as libc::c_int;
    if result as libc::c_ulong != strlen(str) {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn process_macros(
    mut input_buffer: *mut libc::c_char,
    mut output_buffer: *mut libc::c_char,
    mut buffer_length: libc::c_int,
) -> libc::c_int {
    let mut temp_buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut in_macro: libc::c_int = 0;
    let mut arg_index: libc::c_int = 0 as libc::c_int;
    let mut selected_macro: *mut libc::c_char = 0 as *mut libc::c_char;
    strcpy(output_buffer, b"\0" as *const u8 as *const libc::c_char);
    in_macro = 0 as libc::c_int;
    temp_buffer = my_strsep(
        &mut input_buffer,
        b"$\0" as *const u8 as *const libc::c_char,
    );
    while !temp_buffer.is_null() {
        selected_macro = 0 as *mut libc::c_char;
        if in_macro == 0 as libc::c_int {
            if (strlen(output_buffer)).wrapping_add(strlen(temp_buffer))
                < (buffer_length - 1 as libc::c_int) as libc::c_ulong
            {
                strncat(
                    output_buffer,
                    temp_buffer,
                    (buffer_length as libc::c_ulong)
                        .wrapping_sub(strlen(output_buffer))
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                );
                *output_buffer
                    .offset(
                        (buffer_length - 1 as libc::c_int) as isize,
                    ) = '\0' as i32 as libc::c_char;
            }
            in_macro = 1 as libc::c_int;
        } else {
            if (strlen(output_buffer)).wrapping_add(strlen(temp_buffer))
                < (buffer_length - 1 as libc::c_int) as libc::c_ulong
            {
                if strstr(temp_buffer, b"ARG\0" as *const u8 as *const libc::c_char)
                    == temp_buffer
                {
                    arg_index = atoi(temp_buffer.offset(3 as libc::c_int as isize));
                    if arg_index >= 1 as libc::c_int && arg_index <= 16 as libc::c_int {
                        selected_macro = macro_argv[(arg_index - 1 as libc::c_int)
                            as usize];
                    }
                } else if strcmp(temp_buffer, b"\0" as *const u8 as *const libc::c_char)
                    == 0
                {
                    strncat(
                        output_buffer,
                        b"$\0" as *const u8 as *const libc::c_char,
                        (buffer_length as libc::c_ulong)
                            .wrapping_sub(strlen(output_buffer))
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                } else {
                    strncat(
                        output_buffer,
                        b"$\0" as *const u8 as *const libc::c_char,
                        (buffer_length as libc::c_ulong)
                            .wrapping_sub(strlen(output_buffer))
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                    *output_buffer
                        .offset(
                            (buffer_length - 1 as libc::c_int) as isize,
                        ) = '\0' as i32 as libc::c_char;
                    strncat(
                        output_buffer,
                        temp_buffer,
                        (buffer_length as libc::c_ulong)
                            .wrapping_sub(strlen(output_buffer))
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                    *output_buffer
                        .offset(
                            (buffer_length - 1 as libc::c_int) as isize,
                        ) = '\0' as i32 as libc::c_char;
                    strncat(
                        output_buffer,
                        b"$\0" as *const u8 as *const libc::c_char,
                        (buffer_length as libc::c_ulong)
                            .wrapping_sub(strlen(output_buffer))
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                }
                if !selected_macro.is_null() {
                    strncat(
                        output_buffer,
                        if selected_macro.is_null() {
                            b"\0" as *const u8 as *const libc::c_char
                        } else {
                            selected_macro as *const libc::c_char
                        },
                        (buffer_length as libc::c_ulong)
                            .wrapping_sub(strlen(output_buffer))
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                    );
                }
                *output_buffer
                    .offset(
                        (buffer_length - 1 as libc::c_int) as isize,
                    ) = '\0' as i32 as libc::c_char;
            }
            in_macro = 0 as libc::c_int;
        }
        temp_buffer = my_strsep(
            &mut input_buffer,
            b"$\0" as *const u8 as *const libc::c_char,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn process_arguments(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut optchars: [libc::c_char; 2048] = [0; 2048];
    let mut c: libc::c_int = 1 as libc::c_int;
    let mut have_mode: libc::c_int = 0 as libc::c_int;
    let mut option_index: libc::c_int = 0 as libc::c_int;
    static mut long_options: [option; 12] = [
        {
            let mut init = option {
                name: b"config\0" as *const u8 as *const libc::c_char,
                has_arg: 1 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'c' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"inetd\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'i' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"src\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 's' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"no-forking\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'f' as i32,
            };
            init
        },
        {
            let mut init = option {
                name: b"4\0" as *const u8 as *const libc::c_char,
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
                name: b"daemon\0" as *const u8 as *const libc::c_char,
                has_arg: 0 as libc::c_int,
                flag: 0 as *const libc::c_int as *mut libc::c_int,
                val: 'd' as i32,
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
    snprintf(
        optchars.as_mut_ptr(),
        2048 as libc::c_int as libc::c_ulong,
        b"c:hVldi46nsf\0" as *const u8 as *const libc::c_char,
    );
    loop {
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
            86 => {
                show_version = 1 as libc::c_int;
                have_mode = 1 as libc::c_int;
            }
            108 => {
                show_license = 1 as libc::c_int;
            }
            99 => {
                strncpy(
                    config_file.as_mut_ptr(),
                    optarg,
                    ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
                );
                config_file[(::core::mem::size_of::<[libc::c_char; 2048]>()
                    as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as usize] = '\0' as i32 as libc::c_char;
            }
            100 => {
                use_inetd = 0 as libc::c_int;
                have_mode = 1 as libc::c_int;
            }
            105 => {
                use_inetd = 1 as libc::c_int;
                have_mode = 1 as libc::c_int;
            }
            52 => {
                address_family = 2 as libc::c_int;
            }
            54 => {
                address_family = 10 as libc::c_int;
            }
            110 => {
                use_ssl = 0 as libc::c_int;
            }
            115 => {
                use_src = 1 as libc::c_int;
                have_mode = 1 as libc::c_int;
            }
            102 => {
                use_inetd = 0 as libc::c_int;
                no_forking = 1 as libc::c_int;
                have_mode = 1 as libc::c_int;
            }
            _ => return -(1 as libc::c_int),
        }
    }
    if have_mode == 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
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
