#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

#[test]
fn intercept_exec() {
    let mut exit_status = 0;
    {
        let watcher = sandbox::events::ClosureWatcher::new(Box::new(|&mut:event: &sandbox::events::Event| {
            match event.state {
                sandbox::events::State::Exit(st) =>
                    exit_status = st,
                _ => event.cont()
            }
        }));
        let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
        let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watcher));
        sbox.spawn();
        loop {
            if !sbox.is_running() {
                break
            }
            sbox.tick()
        }
    }
    assert!(exit_status == 0);
}

