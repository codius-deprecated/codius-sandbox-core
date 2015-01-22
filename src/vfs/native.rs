use vfs;
use io;
use std::io::{File, Open, ReadWrite, IoResult};
use std::os::unix::prelude::AsRawFd;

pub struct NativeFS {
    root: Path
}

impl NativeFS {
    pub fn new(root: Path) -> Self {
        NativeFS {
            root: root
        }
    }
}

impl vfs::Filesystem for NativeFS {
    #[allow(unstable)]
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> IoResult<i32> {
        println!("Opening {:?}", self.root.join(path));
        let f = File::open_mode(&self.root.join(path), Open, ReadWrite);
        match f {
            Ok(fd) => Ok(fd.as_raw_fd()),
            Err(e) => Err(e)
        }
    }

    fn do_access(&self, path: &str) {
    }
}

impl io::Streaming for NativeFS {
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

