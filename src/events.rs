extern crate "posix-ipc" as ipc;
extern crate ptrace;

#[derive(Show)]
pub enum Event {
    None,
    Trap,
    Signal(ipc::signals::Signal),
    Exit(isize),
    PTrace(ptrace::Event),
    EnteredMain,
    Released(ipc::signals::Signal)
}
