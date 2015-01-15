extern crate "codius-sandbox-core" as sandbox;
extern crate seccomp;
extern crate ptrace;

use std::num::FromPrimitive;

#[main]
fn main() {
    let argv = ["/usr/bin/ls"];
    let exec = sandbox::executors::Execv::new(&argv);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    loop {
        let mut e = sbox.tick();
        match e.state {
            sandbox::events::State::Exit(st) => {
                println!("Child exited with {:?}", st);
                e.cont();
                break;
            },
            sandbox::events::State::EnteredMain => {
                println!("Child has entered main()");
                e.cont();
            },
            sandbox::events::State::Signal(s) => {
                println!("Got signal {:?}", s);
                e.cont();
            },
            sandbox::events::State::Seccomp(call) => {
                let s: seccomp::Syscall = FromPrimitive::from_u64(call.call).expect("Unknown syscall");
                println!("Attemped syscall {:?}", s);
                e.cont();
            },
            sandbox::events::State::None => {},
            _ => {
                panic!("Unhandled sandbox event {:?}", e);
            }
        }
    }
}
