extern crate "codius-sandbox-core" as sandbox;
extern crate seccomp;
extern crate ptrace;

use std::io::{File, Open, ReadWrite, IoResult, IoError};
use std::num::FromPrimitive;
use std::os;
use std::str;
use std::os::unix::prelude::AsRawFd;
use sandbox::events;
use sandbox::vfs;
use sandbox::io;

#[main]
fn main() {
    let args = os::args();
    let mut argv = Vec::new();
    let mut i = args.iter();
    i.next();
    for arg in i {
        argv.push(str::from_utf8(arg.as_bytes()).ok().expect("Invalid argv"));
    }
    let exec = sandbox::executors::Execv::new(argv.as_slice());
    let mut watcher = PrintWatcher {vfs: vfs::VFS::new()};
    watcher.vfs.mount_filesystem("/", Box::new(NativeFS::new(Path::new("/"))));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watcher));
    sbox.spawn();
    loop {
        if !sbox.is_running() {
            break
        }
        sbox.tick();
    }
}

struct NativeFS {
    root: Path
}

impl NativeFS {
    pub fn new(root: Path) -> Self {
        NativeFS {
            root: root
        }
    }
}

impl sandbox::vfs::Filesystem for NativeFS {
    fn do_open(&mut self, path: &str, flags: i32, mode: i32) -> std::io::IoResult<i32> {
        println!("Opening {:?}", self.root.join(path));
        let f = File::open_mode(&self.root.join(path), Open, ReadWrite);
        match f {
            Ok(fd) => sandbox::io::Handle::new(self, fd.as_raw_fd() as isize),
            Err(_) => sandbox::io::Handle::new(self, -1)
        }
        Err(IoError::from_errno(1, false))
    }

    fn do_access(&self, path: &str) {
    }
}

impl sandbox::io::Streaming for NativeFS {
    fn do_write(&mut self, handle: &sandbox::io::Handle, buf: &[u8]) -> IoResult<isize> {
        Ok(0)
    }

    fn do_read(&self, handle: &sandbox::io::Handle, buf: &mut [u8]) -> IoResult<isize> {
        Ok(0)
    }

    fn do_close(&mut self, handle: &sandbox::io::Handle) -> IoResult<()> {
        Ok(())
    }
}

struct PrintWatcher<'a> {
    vfs: sandbox::vfs::VFS<'a>
}

impl<'a> events::Watcher for PrintWatcher<'a> {
    fn notify_event(&mut self, event: &events::Event) {
        match event.state {
            sandbox::events::State::Exit(st) => {
                println!("Child exited with {:?}", st);
                event.cont();
            },
            sandbox::events::State::EnteredMain => {
                println!("Child has entered main()");
                event.cont();
            },
            sandbox::events::State::Signal(s) => {
                println!("Got signal {:?}", s);
                event.cont();
            },
            sandbox::events::State::Seccomp(_) => {
                let mut e = events::Syscall::from_event(*event).expect("Not a syscall?");
                (&mut self.vfs as &mut events::SyscallHandler).handle_syscall(&mut e);
            },
            sandbox::events::State::None => {},
            _ => {
                panic!("Unhandled sandbox event {:?}", event);
            }
        }
    }
}
