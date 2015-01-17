extern crate "posix-ipc" as ipc;
extern crate libc;
extern crate ptrace;

use waitpid;

#[derive(Show, Copy)]
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

#[derive(Show, Copy)]
pub struct Event {
    pub state: State,
    pid: libc::pid_t,
}

#[derive(Show, Copy)]
pub struct Syscall {
    pub call: ptrace::Syscall,
    pub pid: libc::pid_t,
    finished: bool
}

impl Syscall {
    pub fn from_event(event: Event) -> Option<Syscall> {
        match event.state {
            State::Seccomp(call) => Option::Some(Syscall{pid: event.pid, call: call, finished: false}),
            _ => Option::None
        }
    }

    pub fn finish(&mut self, returnVal: ptrace::Word) {
        assert!(!self.finished);
        self.call.call = -1;
        self.call.returnVal = returnVal;
        self.finished = true;
        self.call.write().ok().expect("Could not write registers");
        ptrace::cont(self.pid, ipc::signals::Signal::None);
    }

    pub fn finish_default(&mut self) {
        assert!(!self.finished);
        self.finished = true;
        self.call.write().ok().expect("Could not write registers");
        ptrace::cont(self.pid, ipc::signals::Signal::None);
    }

    pub fn kill(&mut self) {
        assert!(!self.finished);
        self.finished = true;
        ptrace::cont(self.pid, ipc::signals::Signal::Kill);
    }
}

impl Event {
    pub fn new(res: waitpid::WaitResult, event_state: State) -> Self {
        Event {
            pid: res.pid,
            state: event_state,
        }
    }

    pub fn cont(&self) {
        ptrace::cont(self.pid, ipc::signals::Signal::None);
    }

    pub fn kill(&self) {
        ptrace::cont(self.pid, ipc::signals::Signal::Kill);
    }
}

pub struct ClosureWatcher<'a> {
    f: Box<FnMut(&Event) + 'a>
}

impl<'a> ClosureWatcher<'a> {
    pub fn new(f: Box<FnMut(&Event) + 'a>) -> ClosureWatcher<'a> {
        ClosureWatcher {
            f: f
        }
    }
}

impl<'a> Watcher for ClosureWatcher<'a> {
    fn notify_event(&mut self, event: &Event) {
        (self.f)(event);
    }
}

pub trait Watcher {
    fn notify_event(&mut self, event: &Event);
}

pub trait SyscallHandler {
    fn handle_syscall(&mut self, call: &mut Syscall);
}
