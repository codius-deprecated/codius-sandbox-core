extern crate "codius-sandbox-core" as sandbox;
extern crate seccomp;
extern crate ptrace;

use std::num::FromPrimitive;
use std::os;
use std::str;
use sandbox::events;

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
    let watcher = PrintWatcher;
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watcher));
    sbox.spawn();
    loop {
        if !sbox.is_running() {
            break
        }
        sbox.tick();
    }
}

struct PrintWatcher;

impl events::SyscallHandler for PrintWatcher {
    fn handle_syscall(&mut self, call: &mut events::Syscall) {
        println!("Got syscall {:?}", call);
        call.finish(0);
    }
}

impl events::Watcher for PrintWatcher {
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
                (self as &mut events::SyscallHandler).handle_syscall(&mut e);
            },
            sandbox::events::State::None => {},
            _ => {
                panic!("Unhandled sandbox event {:?}", event);
            }
        }
    }
}
