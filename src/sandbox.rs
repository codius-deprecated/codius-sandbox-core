#[allow(unstable)]
extern crate libc;

use executors::Executor;

pub struct Sandbox<'a> {
    pid: libc::pid_t,
    executor: Box<Executor + 'a>
}

impl<'a> Sandbox<'a> {
    pub fn new(exec: Box<Executor + 'a>) -> Sandbox<'a> {
        Sandbox {
            pid: -1,
            executor: exec
        }
    }

    fn exec_child(&mut self) {
        self.executor.exec();
    }

    fn trace_child(&self) {
        // Stub
    }

    pub fn exec(&mut self) {
        self.pid = unsafe { fork() };
        match self.pid {
            0 => self.exec_child(),
            _ => self.trace_child()
        }
    }
}

extern "C" {
    fn fork() -> libc::pid_t;
}
