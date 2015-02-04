use vfs;
use io;
use std::old_io::{File, Read, Open, ReadWrite, IoResult, FileStat, IoError, IoErrorKind};
use std::os::unix::prelude::AsRawFd;
use std::old_io::fs;
use std::collections::HashMap;

pub struct NativeFS {
    root: Path,
    fd_map: HashMap<i32, Box<File>>
}

impl NativeFS {
    pub fn new(root: Path) -> Self {
        NativeFS {
            root: root,
            fd_map: HashMap::new()
        }
    }

    fn get_file(&mut self, handle: &io::Handle) -> Result<&mut File, IoError> {
        match self.fd_map.get_mut(&handle.get_local_fd()) {
            Some(f) => Ok(&mut **f),
            None => Err(IoError {kind: IoErrorKind::FileNotFound, desc: "No Filesystem mounted", detail: None})
        }
    }
}

impl vfs::Filesystem for NativeFS {
    #[allow(unstable)]
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> IoResult<i32> {
        println!("Opening {:?}", self.root.join(path));
        let f = File::open_mode(&self.root.join(path), Open, Read);
        match f {
            Ok(fd) => {
                let num = fd.as_raw_fd();
                self.fd_map.insert(num, Box::new(fd));
                Ok(num)
            },
            Err(e) => Err(e)
        }
    }

    fn do_access(&self, path: &str) -> IoResult<()>{
        println!("Accessing {:?}", self.root.join(path));
        match fs::stat(&self.root.join(path)) {
            Ok(stat) => {
                Ok(())
            },
            Err(e) => Err(e)
        }
    }

    fn do_stat(&self, path: &str) -> IoResult<FileStat> {
        fs::stat(&self.root.join(path))
    }
}

impl io::Streaming for NativeFS {
    fn do_write(&mut self, handle: &io::Handle, buf: &[u8]) -> IoResult<usize> {
        Ok(0)
    }

    fn do_read(&mut self, handle: &io::Handle, buf: &mut [u8]) -> IoResult<usize> {
        println!("Reading from {:?}", handle.get_local_fd());
        match self.get_file(handle) {
            Ok(f) => f.read(buf),
            Err(e) => Err(e)
        }
    }

    fn do_close(&mut self, handle: &io::Handle) -> IoResult<()> {
        Ok(())
    }
}

