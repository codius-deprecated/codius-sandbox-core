extern crate seccomp;

use io;
use events;
use self::seccomp::Syscall;
use std::collections::HashMap;

pub trait Filesystem {
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> io::Handle;
    fn do_access(&mut self, path: &str);
}

pub struct VFS<'a> {
    filesystems: HashMap<String, Box<Filesystem + 'a>>,
    cwd: String
}

impl<'a> events::SyscallHandler for VFS<'a> {
    fn handle_syscall(&mut self, call: &mut events::Syscall) {
        match call.symbolic {
            Syscall::ACCESS => self.do_access(call),
            Syscall::OPEN => self.do_open(call),
            _ => {
                println!("Got unhandled syscall {:?}", call);
            }
        }
    }
}

impl<'a> VFS<'a> {
    fn get_filesystem(&'a self, path: &str) -> Option<(String, &Filesystem)> {
        //FIXME: Search for longest mount point instead of first match
        let abs_path;
        if (path.chars().next() == Some('.')) {
            abs_path = self.cwd.clone() + path;
        } else {
            abs_path = String::from_str(path);
        }

        for (mount_point, fs) in self.filesystems.iter() {
            if abs_path.starts_with(&mount_point[]) {
                let fs_local_path = abs_path.slice_from(mount_point.len());
                return Some((String::from_str(fs_local_path), &**fs));
            }
        }

        return None;
    }

    pub fn mount_filesystem(&mut self, mount_point: &str, fs: Box<Filesystem + 'a>) {
        self.filesystems.insert(String::from_str(mount_point), fs);
    }

    fn do_access(&mut self, call: &mut events::Syscall) {
        let fname = call.read_string_arg(0);
        let fs = self.get_filesystem(&*fname).expect("no fs");
        println!("Accessed a file: {:?}", fname);
        call.finish_default();
    }

    fn do_open(&mut self, call: &mut events::Syscall) {
        println!("Opened a file: {:?}", call.read_string_arg(0));
        call.finish_default();
    }

    pub fn new() -> VFS<'a> {
        VFS {
            filesystems: HashMap::new(),
            cwd: String::new()
        }
    }
}
