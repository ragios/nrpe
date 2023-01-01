#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
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
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strtok_r(
        __s: *mut libc::c_char,
        __delim: *const libc::c_char,
        __save_ptr: *mut *mut libc::c_char,
    ) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn inet_ntoa(__in: in_addr) -> *mut libc::c_char;
    fn inet_pton(
        __af: libc::c_int,
        __cp: *const libc::c_char,
        __buf: *mut libc::c_void,
    ) -> libc::c_int;
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn logit(priority: libc::c_int, format: *const libc::c_char, _: ...);
    static mut debug: libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
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
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
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
pub type C2RustUnnamed_0 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_0 = 8;
pub const _ISpunct: C2RustUnnamed_0 = 4;
pub const _IScntrl: C2RustUnnamed_0 = 2;
pub const _ISblank: C2RustUnnamed_0 = 1;
pub const _ISgraph: C2RustUnnamed_0 = 32768;
pub const _ISprint: C2RustUnnamed_0 = 16384;
pub const _ISspace: C2RustUnnamed_0 = 8192;
pub const _ISxdigit: C2RustUnnamed_0 = 4096;
pub const _ISdigit: C2RustUnnamed_0 = 2048;
pub const _ISalpha: C2RustUnnamed_0 = 1024;
pub const _ISlower: C2RustUnnamed_0 = 512;
pub const _ISupper: C2RustUnnamed_0 = 256;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ip_acl {
    pub family: libc::c_int,
    pub addr: in_addr,
    pub mask: in_addr,
    pub addr6: in6_addr,
    pub mask6: in6_addr,
    pub next: *mut ip_acl,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dns_acl {
    pub domain: [libc::c_char; 255],
    pub next: *mut dns_acl,
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
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
static mut ip_acl_head: *mut ip_acl = 0 as *const ip_acl as *mut ip_acl;
static mut ip_acl_prev: *mut ip_acl = 0 as *const ip_acl as *mut ip_acl;
static mut dns_acl_head: *mut dns_acl = 0 as *const dns_acl as *mut dns_acl;
static mut dns_acl_prev: *mut dns_acl = 0 as *const dns_acl as *mut dns_acl;
#[no_mangle]
pub unsafe extern "C" fn isvalidchar(mut c: libc::c_int) -> libc::c_int {
    if !(c & !(0x7f as libc::c_int) == 0 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if *(*__ctype_b_loc()).offset(c as isize) as libc::c_int
        & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int != 0
    {
        return 1 as libc::c_int;
    }
    if *(*__ctype_b_loc()).offset(c as isize) as libc::c_int
        & _ISalpha as libc::c_int as libc::c_ushort as libc::c_int != 0
    {
        return 2 as libc::c_int;
    }
    if *(*__ctype_b_loc()).offset(c as isize) as libc::c_int
        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int != 0
    {
        return 3 as libc::c_int;
    }
    match c {
        46 => return 4 as libc::c_int,
        47 => return 5 as libc::c_int,
        45 => return 6 as libc::c_int,
        44 => return 7 as libc::c_int,
        _ => return 0 as libc::c_int,
    };
}
#[no_mangle]
pub unsafe extern "C" fn acl_substring(
    mut string: *mut libc::c_char,
    mut s: libc::c_int,
    mut e: libc::c_int,
) -> *mut libc::c_char {
    let mut substring: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = e - s;
    if len < 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    substring = malloc((len + 1 as libc::c_int) as libc::c_ulong) as *mut libc::c_char;
    if substring.is_null() {
        return 0 as *mut libc::c_char;
    }
    memmove(
        substring as *mut libc::c_void,
        string.offset(s as isize) as *const libc::c_void,
        (len + 1 as libc::c_int) as libc::c_ulong,
    );
    return substring;
}
#[no_mangle]
pub unsafe extern "C" fn add_ipv4_to_acl(mut ipv4: *mut libc::c_char) -> libc::c_int {
    let mut state: libc::c_int = 0 as libc::c_int;
    let mut octet: libc::c_int = 0 as libc::c_int;
    let mut index: libc::c_int = 0 as libc::c_int;
    let mut data: [libc::c_int; 5] = [0; 5];
    let mut len: libc::c_int = strlen(ipv4) as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut ip: libc::c_ulong = 0;
    let mut mask: libc::c_ulong = 0;
    let mut ip_acl_curr: *mut ip_acl = 0 as *mut ip_acl;
    if debug == 1 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"add_ipv4_to_acl: checking ip-address >%s<\0" as *const u8
                as *const libc::c_char,
            ipv4,
        );
    }
    if len < 7 as libc::c_int || len > 18 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"add_ipv4_to_acl: Error, ip-address >%s< incorrect length\0" as *const u8
                as *const libc::c_char,
            ipv4,
        );
        return 0 as libc::c_int;
    }
    data[4 as libc::c_int as usize] = 32 as libc::c_int;
    i = 0 as libc::c_int;
    while i < len {
        if state == -(1 as libc::c_int) {
            if debug == 1 as libc::c_int {
                logit(
                    6 as libc::c_int,
                    b"add_ipv4_to_acl: Error, ip-address >%s< incorrect format, continue with next check ...\0"
                        as *const u8 as *const libc::c_char,
                    ipv4,
                );
            }
            return 0 as libc::c_int;
        }
        c = *ipv4.offset(i as isize) as libc::c_int;
        match c {
            48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 56 | 57 => {
                octet = octet * 10 as libc::c_int + (c - '0' as i32);
                match state {
                    0 | 2 | 4 | 6 | 8 => {
                        state += 1;
                    }
                    _ => {}
                }
            }
            46 => {
                match state {
                    1 | 3 | 5 => {
                        let fresh0 = index;
                        index = index + 1;
                        data[fresh0 as usize] = octet;
                        octet = 0 as libc::c_int;
                        state += 1;
                    }
                    _ => {
                        state = -(1 as libc::c_int);
                    }
                }
            }
            47 => {
                match state {
                    7 => {
                        let fresh1 = index;
                        index = index + 1;
                        data[fresh1 as usize] = octet;
                        octet = 0 as libc::c_int;
                        state += 1;
                    }
                    _ => {
                        state = -(1 as libc::c_int);
                    }
                }
            }
            _ => {
                state = -(1 as libc::c_int);
            }
        }
        i += 1;
    }
    match state {
        7 | 9 => {
            data[index as usize] = octet;
        }
        _ => {
            logit(
                6 as libc::c_int,
                b"add_ipv4_to_acl: Error, ip-address >%s< bad state\0" as *const u8
                    as *const libc::c_char,
                ipv4,
            );
            return 0 as libc::c_int;
        }
    }
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int {
        if data[i as usize] < 0 as libc::c_int || data[i as usize] > 255 as libc::c_int {
            logit(
                3 as libc::c_int,
                b"Invalid IPv4 address/network format(%s) in allowed_hosts option\n\0"
                    as *const u8 as *const libc::c_char,
                ipv4,
            );
            return 0 as libc::c_int;
        }
        i += 1;
    }
    if data[4 as libc::c_int as usize] < 0 as libc::c_int
        || data[4 as libc::c_int as usize] > 32 as libc::c_int
    {
        logit(
            3 as libc::c_int,
            b"Invalid IPv4 network mask format(%s) in allowed_hosts option\n\0"
                as *const u8 as *const libc::c_char,
            ipv4,
        );
        return 0 as libc::c_int;
    }
    ip = __bswap_32(
        ((data[0 as libc::c_int as usize] << 24 as libc::c_int)
            + (data[1 as libc::c_int as usize] << 16 as libc::c_int)
            + (data[2 as libc::c_int as usize] << 8 as libc::c_int)
            + data[3 as libc::c_int as usize]) as __uint32_t,
    ) as libc::c_ulong;
    mask = __bswap_32(
        (-(1 as libc::c_int) << 32 as libc::c_int - data[4 as libc::c_int as usize])
            as __uint32_t,
    ) as libc::c_ulong;
    if ip & mask != ip {
        logit(
            3 as libc::c_int,
            b"IP address and mask do not match in %s\n\0" as *const u8
                as *const libc::c_char,
            ipv4,
        );
        return 0 as libc::c_int;
    }
    ip_acl_curr = malloc(::core::mem::size_of::<ip_acl>() as libc::c_ulong)
        as *mut ip_acl;
    if ip_acl_curr.is_null() {
        logit(
            3 as libc::c_int,
            b"Can't allocate memory for ACL, malloc error\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    (*ip_acl_curr).family = 2 as libc::c_int;
    (*ip_acl_curr).addr.s_addr = ip as in_addr_t;
    (*ip_acl_curr).mask.s_addr = mask as in_addr_t;
    (*ip_acl_curr).next = 0 as *mut ip_acl;
    if ip_acl_head.is_null() {
        ip_acl_head = ip_acl_curr;
    } else {
        (*ip_acl_prev).next = ip_acl_curr;
    }
    ip_acl_prev = ip_acl_curr;
    if debug == 1 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"add_ipv4_to_acl: ip-address >%s< correct, adding.\0" as *const u8
                as *const libc::c_char,
            ipv4,
        );
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn add_ipv6_to_acl(mut ipv6: *mut libc::c_char) -> libc::c_int {
    let mut ipv6tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut addr_part: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut mask_part: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed {
            __u6_addr8: [0; 16],
        },
    };
    let mut mask: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed {
            __u6_addr8: [0; 16],
        },
    };
    let mut maskval: libc::c_int = 0;
    let mut byte: libc::c_int = 0;
    let mut bit: libc::c_int = 0;
    let mut nbytes: libc::c_int = (::core::mem::size_of::<[uint8_t; 16]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<uint8_t>() as libc::c_ulong) as libc::c_int;
    let mut x: libc::c_int = 0;
    let mut ip_acl_curr: *mut ip_acl = 0 as *mut ip_acl;
    ipv6tmp = strdup(ipv6);
    if ipv6tmp.is_null() {
        logit(
            3 as libc::c_int,
            b"Memory allocation failed for copy of address: %s\n\0" as *const u8
                as *const libc::c_char,
            ipv6,
        );
        return 0 as libc::c_int;
    }
    addr_part = ipv6tmp;
    mask_part = strchr(ipv6tmp, '/' as i32);
    if !mask_part.is_null() {
        *mask_part = '\0' as i32 as libc::c_char;
        mask_part = mask_part.offset(1);
    }
    if inet_pton(
        10 as libc::c_int,
        addr_part,
        &mut addr as *mut in6_addr as *mut libc::c_void,
    ) <= 0 as libc::c_int
    {
        free(ipv6tmp as *mut libc::c_void);
        return 0 as libc::c_int;
    }
    if !mask_part.is_null() && *mask_part as libc::c_int != 0 {
        maskval = atoi(mask_part);
        if maskval < 0 as libc::c_int || maskval > 128 as libc::c_int {
            free(ipv6tmp as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        x = 0 as libc::c_int;
        while x < nbytes {
            mask.__in6_u.__u6_addr8[x as usize] = 0 as libc::c_int as uint8_t;
            x += 1;
        }
        byte = 0 as libc::c_int;
        bit = 7 as libc::c_int;
        while maskval > 0 as libc::c_int {
            mask
                .__in6_u
                .__u6_addr8[byte
                as usize] = (mask.__in6_u.__u6_addr8[byte as usize] as libc::c_int
                | (1 as libc::c_int) << bit) as uint8_t;
            bit -= 1 as libc::c_int;
            if bit < 0 as libc::c_int {
                bit = 7 as libc::c_int;
                byte += 1;
            }
            maskval -= 1;
        }
    } else {
        x = 0 as libc::c_int;
        while x < nbytes {
            mask.__in6_u.__u6_addr8[x as usize] = 0xff as libc::c_int as uint8_t;
            x += 1;
        }
    }
    ip_acl_curr = malloc(::core::mem::size_of::<ip_acl>() as libc::c_ulong)
        as *mut ip_acl;
    if ip_acl_curr.is_null() {
        logit(
            3 as libc::c_int,
            b"Memory allocation failed for ACL: %s\n\0" as *const u8
                as *const libc::c_char,
            ipv6,
        );
        return 0 as libc::c_int;
    }
    (*ip_acl_curr).family = 10 as libc::c_int;
    x = 0 as libc::c_int;
    while x < nbytes {
        (*ip_acl_curr)
            .addr6
            .__in6_u
            .__u6_addr8[x
            as usize] = (addr.__in6_u.__u6_addr8[x as usize] as libc::c_int
            & mask.__in6_u.__u6_addr8[x as usize] as libc::c_int) as uint8_t;
        (*ip_acl_curr)
            .mask6
            .__in6_u
            .__u6_addr8[x as usize] = mask.__in6_u.__u6_addr8[x as usize];
        x += 1;
    }
    (*ip_acl_curr).next = 0 as *mut ip_acl;
    if ip_acl_head.is_null() {
        ip_acl_head = ip_acl_curr;
    } else {
        (*ip_acl_prev).next = ip_acl_curr;
    }
    ip_acl_prev = ip_acl_curr;
    free(ipv6tmp as *mut libc::c_void);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn add_domain_to_acl(
    mut domain: *mut libc::c_char,
) -> libc::c_int {
    let mut state: libc::c_int = 0 as libc::c_int;
    let mut len: libc::c_int = strlen(domain) as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut dns_acl_curr: *mut dns_acl = 0 as *mut dns_acl;
    if len > 63 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"ADD_DOMAIN_TO_ACL: Error, did not add >%s< to acl list, too long!\0"
                as *const u8 as *const libc::c_char,
            domain,
        );
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < len {
        c = *domain.offset(i as isize) as libc::c_int;
        match isvalidchar(c) {
            1 => {
                state = 1 as libc::c_int;
            }
            2 => {
                match state {
                    0 | 1 | 5 | 6 => {
                        state = 1 as libc::c_int;
                    }
                    2 | 3 | 4 => {
                        state += 1;
                    }
                    _ => {}
                }
            }
            4 => {
                match state {
                    0 | 2 => {
                        state = -(1 as libc::c_int);
                    }
                    _ => {
                        state = 2 as libc::c_int;
                    }
                }
            }
            6 => {
                match state {
                    0 | 2 => {
                        state = -(1 as libc::c_int);
                    }
                    _ => {
                        state = 6 as libc::c_int;
                    }
                }
            }
            _ => {
                logit(
                    6 as libc::c_int,
                    b"ADD_DOMAIN_TO_ACL: Error, did not add >%s< to acl list, invalid chars!\0"
                        as *const u8 as *const libc::c_char,
                    domain,
                );
                return 0 as libc::c_int;
            }
        }
        i += 1;
    }
    match state {
        1 | 4 | 5 => {
            dns_acl_curr = malloc(::core::mem::size_of::<dns_acl>() as libc::c_ulong)
                as *mut dns_acl;
            if dns_acl_curr.is_null() {
                logit(
                    3 as libc::c_int,
                    b"Can't allocate memory for ACL, malloc error\n\0" as *const u8
                        as *const libc::c_char,
                );
                return 0 as libc::c_int;
            }
            strcpy(((*dns_acl_curr).domain).as_mut_ptr(), domain);
            (*dns_acl_curr).next = 0 as *mut dns_acl;
            if dns_acl_head.is_null() {
                dns_acl_head = dns_acl_curr;
            } else {
                (*dns_acl_prev).next = dns_acl_curr;
            }
            dns_acl_prev = dns_acl_curr;
            if debug == 1 as libc::c_int {
                logit(
                    6 as libc::c_int,
                    b"ADD_DOMAIN_TO_ACL: added >%s< to acl list!\0" as *const u8
                        as *const libc::c_char,
                    domain,
                );
            }
            return 1 as libc::c_int;
        }
        _ => {
            logit(
                6 as libc::c_int,
                b"ADD_DOMAIN_TO_ACL: ERROR, did not add >%s< to acl list, check allowed_host in config file!\0"
                    as *const u8 as *const libc::c_char,
                domain,
            );
            return 0 as libc::c_int;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn is_an_allowed_host(
    mut family: libc::c_int,
    mut host: *mut libc::c_void,
) -> libc::c_int {
    let mut ip_acl_curr: *mut ip_acl = ip_acl_head;
    let mut nbytes: libc::c_int = 0;
    let mut x: libc::c_int = 0;
    let mut dns_acl_curr: *mut dns_acl = dns_acl_head;
    let mut addr: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut addr6: sockaddr_in6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut tmp: in_addr = in_addr { s_addr: 0 };
    while !ip_acl_curr.is_null() {
        if (*ip_acl_curr).family == family {
            match (*ip_acl_curr).family {
                2 => {
                    if debug == 1 as libc::c_int {
                        tmp.s_addr = (*(host as *mut in_addr)).s_addr;
                        logit(
                            6 as libc::c_int,
                            b"is_an_allowed_host (AF_INET): is host >%s< an allowed host >%s<\n\0"
                                as *const u8 as *const libc::c_char,
                            inet_ntoa(tmp),
                            inet_ntoa((*ip_acl_curr).addr),
                        );
                    }
                    if (*(host as *mut in_addr)).s_addr & (*ip_acl_curr).mask.s_addr
                        == (*ip_acl_curr).addr.s_addr
                    {
                        if debug == 1 as libc::c_int {
                            logit(
                                6 as libc::c_int,
                                b"is_an_allowed_host (AF_INET): host is in allowed host list!\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        return 1 as libc::c_int;
                    }
                }
                10 => {
                    nbytes = (::core::mem::size_of::<[uint8_t; 16]>() as libc::c_ulong)
                        .wrapping_div(::core::mem::size_of::<uint8_t>() as libc::c_ulong)
                        as libc::c_int;
                    x = 0 as libc::c_int;
                    while x < nbytes {
                        if (*(host as *mut in6_addr)).__in6_u.__u6_addr8[x as usize]
                            as libc::c_int
                            & (*ip_acl_curr).mask6.__in6_u.__u6_addr8[x as usize]
                                as libc::c_int
                            != (*ip_acl_curr).addr6.__in6_u.__u6_addr8[x as usize]
                                as libc::c_int
                        {
                            break;
                        }
                        x += 1;
                    }
                    if x == nbytes {
                        return 1 as libc::c_int;
                    }
                }
                _ => {}
            }
        }
        ip_acl_curr = (*ip_acl_curr).next;
    }
    while !dns_acl_curr.is_null() {
        if getaddrinfo(
            ((*dns_acl_curr).domain).as_mut_ptr(),
            0 as *const libc::c_char,
            0 as *const addrinfo,
            &mut res,
        ) == 0
        {
            ai = res;
            while !ai.is_null() {
                if (*ai).ai_family == family {
                    match (*ai).ai_family {
                        2 => {
                            if debug == 1 as libc::c_int {
                                tmp.s_addr = (*(host as *mut in_addr)).s_addr;
                                logit(
                                    6 as libc::c_int,
                                    b"is_an_allowed_host (AF_INET): test match host >%s< for allowed host >%s<\n\0"
                                        as *const u8 as *const libc::c_char,
                                    inet_ntoa(tmp),
                                    ((*dns_acl_curr).domain).as_mut_ptr(),
                                );
                            }
                            addr = (*ai).ai_addr as *mut sockaddr_in;
                            if (*addr).sin_addr.s_addr
                                == (*(host as *mut in_addr)).s_addr
                            {
                                if debug == 1 as libc::c_int {
                                    logit(
                                        6 as libc::c_int,
                                        b"is_an_allowed_host (AF_INET): host is in allowed host list!\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                }
                                return 1 as libc::c_int;
                            }
                        }
                        10 => {
                            if debug == 1 as libc::c_int {
                                let mut formattedStr: [libc::c_char; 46] = [0; 46];
                                inet_ntop(
                                    (*ai).ai_family,
                                    &mut (*((*ai).ai_addr as *mut sockaddr_in6)).sin6_addr
                                        as *mut in6_addr as *mut libc::c_void,
                                    formattedStr.as_mut_ptr(),
                                    46 as libc::c_int as socklen_t,
                                );
                                logit(
                                    6 as libc::c_int,
                                    b"is_an_allowed_host (AF_INET6): test match host against >%s< for allowed host >%s<\n\0"
                                        as *const u8 as *const libc::c_char,
                                    formattedStr.as_mut_ptr(),
                                    ((*dns_acl_curr).domain).as_mut_ptr(),
                                );
                            }
                            let mut resolved: *mut in6_addr = &mut (*((*ai).ai_addr
                                as *mut sockaddr_in6))
                                .sin6_addr;
                            memcpy(
                                &mut addr6 as *mut sockaddr_in6 as *mut libc::c_char
                                    as *mut libc::c_void,
                                (*ai).ai_addr as *const libc::c_void,
                                ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong,
                            );
                            if memcmp(
                                &mut addr6.sin6_addr as *mut in6_addr
                                    as *const libc::c_void,
                                host,
                                ::core::mem::size_of::<in6_addr>() as libc::c_ulong,
                            ) == 0
                            {
                                if debug == 1 as libc::c_int {
                                    logit(
                                        6 as libc::c_int,
                                        b"is_an_allowed_host (AF_INET6): host is in allowed host list!\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                }
                                return 1 as libc::c_int;
                            }
                        }
                        _ => {}
                    }
                }
                ai = (*ai).ai_next;
            }
        }
        dns_acl_curr = (*dns_acl_curr).next;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn trim(mut src: *mut libc::c_char, mut dest: *mut libc::c_char) {
    let mut sptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dptr: *mut libc::c_char = 0 as *mut libc::c_char;
    sptr = src;
    while *(*__ctype_b_loc()).offset(*sptr as libc::c_int as isize) as libc::c_int
        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int != 0
        && *sptr as libc::c_int != 0
    {
        sptr = sptr.offset(1);
    }
    dptr = dest;
    while *(*__ctype_b_loc()).offset(*sptr as libc::c_int as isize) as libc::c_int
        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int == 0
        && *sptr as libc::c_int != 0
    {
        *dptr = *sptr;
        sptr = sptr.offset(1);
        dptr = dptr.offset(1);
    }
    *dptr = '\0' as i32 as libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn parse_allowed_hosts(mut allowed_hosts: *mut libc::c_char) {
    let mut hosts: *mut libc::c_char = strdup(allowed_hosts);
    let mut saveptr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tok: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut delim: *const libc::c_char = b",\0" as *const u8 as *const libc::c_char;
    let mut trimmed_tok: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut add_to_acl: libc::c_int = 0 as libc::c_int;
    if debug == 1 as libc::c_int {
        logit(
            6 as libc::c_int,
            b"parse_allowed_hosts: parsing the allowed host string >%s< to add to ACL list\n\0"
                as *const u8 as *const libc::c_char,
            allowed_hosts,
        );
    }
    tok = strtok_r(hosts, delim, &mut saveptr);
    while !tok.is_null() {
        trimmed_tok = malloc(
            (::core::mem::size_of::<libc::c_char>() as libc::c_ulong)
                .wrapping_mul(
                    (strlen(tok)).wrapping_add(1 as libc::c_int as libc::c_ulong),
                ),
        ) as *mut libc::c_char;
        trim(tok, trimmed_tok);
        if debug == 1 as libc::c_int {
            logit(
                7 as libc::c_int,
                b"parse_allowed_hosts: ADDING this record (%s) to ACL list!\n\0"
                    as *const u8 as *const libc::c_char,
                trimmed_tok,
            );
        }
        if strlen(trimmed_tok) > 0 as libc::c_int as libc::c_ulong {
            if !(strchr(trimmed_tok, ':' as i32)).is_null() {
                add_to_acl = add_ipv6_to_acl(trimmed_tok);
            } else {
                add_to_acl = add_ipv4_to_acl(trimmed_tok);
            }
            if add_to_acl == 0 && add_domain_to_acl(trimmed_tok) == 0 {
                logit(
                    3 as libc::c_int,
                    b"Can't add to ACL this record (%s). Check allowed_hosts option!\n\0"
                        as *const u8 as *const libc::c_char,
                    trimmed_tok,
                );
            } else if debug == 1 as libc::c_int {
                logit(
                    7 as libc::c_int,
                    b"parse_allowed_hosts: Record added to ACL list!\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
        }
        free(trimmed_tok as *mut libc::c_void);
        tok = strtok_r(0 as *mut libc::c_char, delim, &mut saveptr);
    }
    free(hosts as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn prefix_from_mask(mut mask: in_addr) -> libc::c_uint {
    let mut prefix: libc::c_int = 0 as libc::c_int;
    let mut bit: libc::c_ulong = 1 as libc::c_int as libc::c_ulong;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        if mask.s_addr as libc::c_ulong & bit != 0 {
            prefix += 1;
        }
        bit = bit << 1 as libc::c_int;
        i += 1;
    }
    return prefix as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn show_acl_lists() {
    let mut ip_acl_curr: *mut ip_acl = ip_acl_head;
    let mut dns_acl_curr: *mut dns_acl = dns_acl_head;
    logit(
        6 as libc::c_int,
        b"Showing ACL lists for both IP and DOMAIN acl's:\n\0" as *const u8
            as *const libc::c_char,
    );
    while !ip_acl_curr.is_null() {
        logit(
            6 as libc::c_int,
            b"   IP ACL: %s/%u %u\n\0" as *const u8 as *const libc::c_char,
            inet_ntoa((*ip_acl_curr).addr),
            prefix_from_mask((*ip_acl_curr).mask),
            (*ip_acl_curr).addr.s_addr,
        );
        ip_acl_curr = (*ip_acl_curr).next;
    }
    while !dns_acl_curr.is_null() {
        logit(
            6 as libc::c_int,
            b"  DNS ACL: %s\n\0" as *const u8 as *const libc::c_char,
            ((*dns_acl_curr).domain).as_mut_ptr(),
        );
        dns_acl_curr = (*dns_acl_curr).next;
    }
}
