extern crate "posix-ipc" as ipc;
#[allow(unstable)]
extern crate libc;
extern crate ptrace;
extern crate seccomp;

use std::num::FromPrimitive;

use waitpid;

#[derive(Debug, Copy)]
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

#[derive(Debug, Copy)]
pub struct Event {
    pub state: State,
    pid: libc::pid_t,
}

#[derive(Debug, Copy)]
pub struct Syscall {
    pub symbolic: seccomp::Syscall,
    pub call: ptrace::Syscall,
    pub pid: libc::pid_t,
    finished: bool
}

impl Syscall {
    pub fn from_event(event: Event) -> Option<Syscall> {
        match event.state {
            State::Seccomp(call) => Option::Some(
                Syscall {
                    pid: event.pid,
                    call: call,
                    finished: false,
                    symbolic: FromPrimitive::from_u64(call.call).expect("Unknown syscall")
                }
            ),
            _ => Option::None
        }
    }

    pub fn finish(&mut self, return_val: ptrace::Word) {
        assert!(!self.finished);
        self.call.call = -1;
        self.call.returnVal = return_val;
        self.finished = true;
        self.call.write().ok().expect("Could not write registers");
        ptrace::cont(self.pid, ipc::signals::Signal::None).ok().expect("Could not finish event");
    }

    pub fn finish_default(&mut self) {
        assert!(!self.finished);
        self.finished = true;
        self.call.write().ok().expect("Could not write registers");
        ptrace::cont(self.pid, ipc::signals::Signal::None).ok().expect("Could not finish event w/ default");
    }

    pub fn kill(&mut self) {
        assert!(!self.finished);
        self.finished = true;
        ptrace::cont(self.pid, ipc::signals::Signal::Kill).ok().expect("Could not finish event w/ kill");
    }

    pub fn read_string_arg(&self, arg_num: usize) -> String {
        let reader = ptrace::Reader::new(self.pid);
        let s = reader.read_string(self.call.args[arg_num]);
        return String::from_utf8(s).ok().expect("Could not read string argument");
    }

    pub fn write_buf_arg<T: Sized>(&self, arg_num: usize, buf: &T) -> Result<(), usize> {
        let writer = ptrace::Writer::new(self.pid);
        writer.write_object (self.call.args[arg_num], buf)
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
        match self.state {
            State::Signal(sig) => ptrace::cont(self.pid, sig).ok().expect("Could not pass signal through to child"),
            State::Exit(e) => {ptrace::cont(self.pid, ipc::signals::Signal::None);0},
            _ => ptrace::cont(self.pid, ipc::signals::Signal::None).ok().expect("Could not continue child")
        };
    }

    pub fn kill(&self) {
        ptrace::cont(self.pid, ipc::signals::Signal::Kill).ok().expect("Could not kill child");
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
