extern crate "posix-ipc" as ipc;

#[derive(Show)]
pub enum Event {
    Unknown,
    Signal(ipc::signals::Signal),
    Exit(isize)
}
