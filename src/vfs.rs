extern crate seccomp;

use events;
use self::seccomp::Syscall;

pub struct VFS;

impl events::SyscallHandler for VFS {
    fn handle_syscall(&mut self, call: &mut events::Syscall) {
        match call.symbolic {
            Syscall::ACCESS => self.do_access(call),
            Syscall::OPEN => self.do_open(call),
            _ => {
                println!("Got unhandled syscall {:?}", call);
                call.kill();
            }
        }
    }
}

impl VFS {
    fn do_access(&mut self, call: &mut events::Syscall) {
        println!("Accessed a file");
        call.finish_default();
    }

    fn do_open(&mut self, call: &mut events::Syscall) {
        println!("Opened a file");
        call.finish_default();
    }
}
