extern crate "posix-ipc" as ipc;
extern crate libc;
extern crate ptrace;

use waitpid;

#[derive(Show)]
pub enum State {
    None,
    Trap,
    Signal(ipc::signals::Signal),
    Exit(isize),
    PTrace(ptrace::Event),
    EnteredMain,
    Released(ipc::signals::Signal),
    Seccomp(ptrace::Syscall)
}

#[derive(Show)]
pub struct Event {
    pub state: State,
    pid: libc::pid_t,
    handled: bool
}

impl Event {
    pub fn new(res: waitpid::WaitResult, event_state: State) -> Self {
        Event {
            pid: res.pid,
            state: event_state,
            handled: false
        }
    }

    pub fn cont(&mut self) {
        ptrace::cont(self.pid, ipc::signals::Signal::None);
        self.handled = true;
    }

    pub fn kill(&mut self) {
        ptrace::cont(self.pid, ipc::signals::Signal::Kill);
        self.handled = true;
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        match self.state {
            _ => assert!(self.handled)
        }
    }
}
