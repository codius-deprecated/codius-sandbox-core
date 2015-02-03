extern crate "codius-sandbox-core" as sandbox;

use sandbox::vfs;
use sandbox::io;
use std::old_io::*;
use std::cell::RefCell;

struct TestFS {
    called_funcs: RefCell<Vec<&'static str>>
}

impl TestFS {
    pub fn new() -> Self {
        TestFS {
            called_funcs: RefCell::new(Vec::new())
        }
    }
}

impl vfs::Filesystem for TestFS {
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> IoResult<i32> {
        self.called_funcs.borrow_mut().push("open");
        Ok(1)
    }

    fn do_access(&self, path: &str) -> IoResult<()> {
        self.called_funcs.borrow_mut().push("access");
        Ok(())
    }

    fn do_stat(&self, path: &str) -> IoResult<FileStat> {
        self.called_funcs.borrow_mut().push("stat");
        Ok(FileStat {
            size: 0,
            kind: FileType::RegularFile,
            perm: USER_READ | GROUP_READ | OTHER_READ,
            created: 0,
            modified: 0,
            accessed: 0,
            unstable: UnstableFileStat {
                device: 0,
                inode: 0,
                rdev: 0,
                nlink: 0,
                uid: 0,
                gid: 0,
                blksize: 0,
                blocks: 0,
                flags: 0,
                gen: 0
            }
        })
    }
}

impl io::Streaming for TestFS {
    fn do_write(&mut self, handle: &io::Handle, buf: &[u8]) -> IoResult<usize> {
        Ok(0)
    }

    fn do_read(&mut self, handle: &io::Handle, buf: &mut [u8]) -> IoResult<usize> {
        Ok(0)
    }

    fn do_close(&mut self, handle: &io::Handle) -> IoResult<()> {
        Ok(())
    }
}

#[test]
fn test_mounted_fs() {
    let mut vfs = vfs::VFS::new();
    vfs.mount_filesystem("/", Box::new(TestFS::new()));
}
