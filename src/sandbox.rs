#[allow(unstable)]
extern crate libc;
extern crate ptrace;
extern crate "posix-ipc" as ipc;

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
        ptrace::traceme();
        ipc::signals::Signal::Stop.raise();
        self.executor.exec();
    }

    fn trace_child(&self) {
        ptrace::attach(self.pid);
        ipc::signals::Signal::Cont.kill(self.pid);
    }

    pub fn get_pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn release(&mut self, signal: ipc::signals::Signal) {
        ptrace::release(self.pid, signal);
        self.pid = -1;
    }

    pub fn spawn(&mut self) {
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
