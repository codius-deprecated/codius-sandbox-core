extern crate seccomp;

use io;
use events;
use self::seccomp::Syscall;
use std::collections::HashMap;
use std::old_io::{IoResult, IoErrorKind, FileStat};
use std::rc::Rc;
use std::cell::RefCell;

pub mod native;

trait AsErrno {fn to_errno(&self) -> u64;}

impl AsErrno for IoErrorKind {
    fn to_errno(&self) -> u64 {
        -1
    }
}

#[derive(Clone)]
pub struct Handle<'fs> {
    _local_fd: i32,
    _virt_fd: i32,
    _fs: Rc<RefCell<Box<Filesystem + 'fs>>>
}

impl<'fs> io::Handle for Handle<'fs> {
    fn get_local_fd(&self) -> i32 {
        self._local_fd
    }

    fn get_virt_fd(&self) -> i32 {
        self._virt_fd
    }

    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self._fs.borrow_mut().do_read(self, buf)
    }

    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self._fs.borrow_mut().do_write(self, buf)
    }

    fn close(&mut self) -> IoResult<()> {
        self._fs.borrow_mut().do_close(self)
    }
}

impl<'fs> Handle<'fs> {
    pub fn new(fs: Rc<RefCell<Box<Filesystem + 'fs>>>, virt_fd: i32, local_fd: i32) -> Self {
        Handle {
            _local_fd: local_fd,
            _virt_fd: virt_fd,
            _fs: fs
        }
    }
}

pub trait Filesystem: io::Streaming {
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> IoResult<i32>;
    fn do_access(&self, path: &str) -> IoResult<()>;
    fn do_stat(&self, path: &str) -> IoResult<FileStat>;
}

pub type FsRef<'fs> = Rc<RefCell<Box<Filesystem + 'fs>>>;

pub struct VFS<'fs> {
    filesystems: HashMap<String, FsRef<'fs>>,
    cwd: String,
    next_fd: i32,
    open_fds: HashMap<i32, Handle<'fs>>,
    whitelist: Vec<String>
}

impl<'fs> events::SyscallHandler for VFS<'fs> {
    fn handle_syscall(&mut self, call: &mut events::Syscall) {
        match call.symbolic {
            Syscall::ACCESS => self.do_access(call),
            Syscall::OPEN => self.do_open(call),
            Syscall::STAT => self.do_stat(call),
            _ => {
                println!("Got unhandled syscall {:?}", call);
            }
        }
    }
}

impl<'fs> VFS<'fs> {

    fn with_filename_arg<T>(&self, call: &mut events::Syscall, arg_num: usize, f: &mut FnMut(&mut events::Syscall, String, &FsRef<'fs>) -> Option<T>) -> Option<T> {
        match self.get_filesystem_from_arg(call, arg_num) {
            None => {call.finish(2);None},
            Some((path, fs)) => f(call, path, fs)
        }
    }

    fn is_whitelisted(&self, name: &String) -> bool {
        for f in self.whitelist.iter() {
            if f == name {
                return true;
            }
        }
        false
    }

    fn get_filesystem_from_arg(&self, call: &events::Syscall, argnum: usize) -> Option<(String, &FsRef<'fs>)> {
        let fname = call.read_string_arg(argnum);
        if !self.is_whitelisted(&fname) {
            self.get_filesystem(&*fname)
        } else {
            None
        }
    }

    fn get_filesystem(&self, path: &str) -> Option<(String, &FsRef<'fs>)> {
        //FIXME: Search for longest mount point instead of first match
        let abs_path;
        if path.chars().next() == Some('.') {
            abs_path = self.cwd.clone() + path;
        } else {
            abs_path = String::from_str(path);
        }

        for (mount_point, fs) in self.filesystems.iter() {
            if abs_path.starts_with(&mount_point[]) {
                let fs_local_path = abs_path.slice_from(mount_point.len());
                return Some((String::from_str(fs_local_path), fs));
            }
        }

        return None;
    }

    pub fn mount_filesystem(&mut self, mount_point: &str, fs: Box<Filesystem + 'fs>) {
        self.filesystems.insert(String::from_str(mount_point), Rc::new(RefCell::new(fs)));
    }

    fn do_stat(&self, call: &mut events::Syscall) {
        self.with_filename_arg(call, 0, &mut |call, path, fs| {
            Some(match fs.borrow_mut().do_stat(&path[]) {
                Ok(sbuf) => {
                    call.write_buf_arg(0, &Stat {
                        st_dev: sbuf.unstable.device,
                        st_ino: sbuf.unstable.inode,
                        st_mode: sbuf.perm.bits() as i64,
                        st_nlink: sbuf.unstable.nlink,
                        st_uid: sbuf.unstable.uid as i64,
                        st_gid: sbuf.unstable.gid as i64,
                        st_rdev: sbuf.unstable.rdev,
                        st_size: sbuf.size as i64,
                        st_blksize: sbuf.unstable.blksize as i64,
                        st_blocks: sbuf.unstable.blocks as i64,
                        st_atime: sbuf.accessed,
                        st_atime_nsec: 0,
                        st_mtime: sbuf.modified,
                        st_mtime_nsec: 0,
                        st_ctime: sbuf.created,
                        st_ctime_nsec: 0,
                        __pad0: 0,
                        __pad1: 0,
                        __pad2: 0,
                        __pad3: 0
                    });
                    call.finish(0)
                },
                Err(err) => call.finish(err.kind.to_errno())
            })
        });
    }

    fn do_access(&self, call: &mut events::Syscall) {
        self.with_filename_arg(call, 0, &mut |call, path, fs| {
            Some(match fs.borrow_mut().do_access(&path[]) {
                Ok(_) => call.finish(0),
                Err(err) => call.finish(err.kind.to_errno())
            })
        });
    }

    fn do_open(&mut self, call: &mut events::Syscall) {
        match self.with_filename_arg(call, 0, &mut |call, path, fs| {
            match fs.borrow_mut().do_open(&path[], 0, 0) {
                Ok(fd) =>
                    Some(Handle::new(fs.clone(), self.next_fd + 1, fd)),
                Err(err) => {
                    call.finish(err.kind.to_errno());
                    None
                }
            }
        }) {
            Some(fd) => {
                let fd_num = (&fd as &io::Handle).get_virt_fd();
                self.open_fds.insert(fd_num, fd);
                call.finish(fd_num as u64);
            },
            None => {}
        }
    }

    pub fn new() -> VFS<'fs> {
        let mut r = VFS {
            filesystems: HashMap::new(),
            cwd: String::new(),
            next_fd: 0,
            open_fds: HashMap::new(),
            whitelist: Vec::new()
        };

        r.whitelist.push(String::from_str("/lib64/libc.so.6"));
        r.whitelist.push(String::from_str ("/lib64/tls/x86_64/libc.so.6"));
        r.whitelist.push(String::from_str ("/lib64/tls/x86_64/libdl.so.2"));
        r.whitelist.push(String::from_str ("/lib64/tls/x86_64/librt.so.1"));
        r.whitelist.push(String::from_str ("/lib64/tls/x86_64/libpthread.so.0"));
        r.whitelist.push(String::from_str ("/lib64/tls/libc.so.6"));
        r.whitelist.push(String::from_str ("/lib64/tls/libdl.so.2"));
        r.whitelist.push(String::from_str ("/lib64/tls/librt.so.1"));
        r.whitelist.push(String::from_str ("/lib64/tls/libstdc++.so.6"));
        r.whitelist.push(String::from_str ("/lib64/tls/libm.so.6"));
        r.whitelist.push(String::from_str ("/lib64/tls/libgcc_s.so.1"));
        r.whitelist.push(String::from_str ("/lib64/tls/libpthread.so.0"));
        r.whitelist.push(String::from_str ("/lib64/x86_64/libc.so.6"));
        r.whitelist.push(String::from_str ("/lib64/x86_64/libdl.so.2"));
        r.whitelist.push(String::from_str ("/lib64/x86_64/librt.so.1"));
        r.whitelist.push(String::from_str ("/lib64/libc.so.6"));
        r.whitelist.push(String::from_str ("/lib64/libdl.so.2"));
        r.whitelist.push(String::from_str ("/lib64/librt.so.1"));
        r.whitelist.push(String::from_str ("/lib64/libgcc_s.so.1"));
        r.whitelist.push(String::from_str ("/lib64/libpthread.so.0"));

        r.whitelist.push(String::from_str ("/lib64/libstdc++.so.6"));
        r.whitelist.push(String::from_str ("/lib64/libm.so.6"));

        r.whitelist.push(String::from_str ("/etc/ld.so.cache"));
        r.whitelist.push(String::from_str ("/etc/ld.so.preload"));

        r.whitelist.push(String::from_str ("/proc/self/exe"));

        r
    }
}

#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,

    st_mode: i64,
    st_uid: i64,
    st_gid: i64,
    __pad0: i64,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: u64,
    st_atime_nsec: u64,
    st_mtime: u64,
    st_mtime_nsec: u64,
    st_ctime: u64,
    st_ctime_nsec: u64,
    __pad1: i64,
    __pad2: i64,
    __pad3: i64,
}
