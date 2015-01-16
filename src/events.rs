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

#[derive(Show)]
pub struct Event {
    pub state: State,
    pid: libc::pid_t,
}

pub struct Syscall<'a> {
    pub event: &'a Event,
    pub call: ptrace::Syscall
}

impl<'a> Syscall<'a> {
    pub fn from_event(event: &'a Event) -> Option<Syscall<'a>> {
        match event.state {
            State::Seccomp(call) => Option::Some(Syscall{event: event, call: call}),
            _ => Option::None
        }
    }

    pub fn set_return_value(&mut self, value: ptrace::Word) {
        self.call.returnVal = value
    }

    pub fn skip(&mut self) {
        self.call.call = -1
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
