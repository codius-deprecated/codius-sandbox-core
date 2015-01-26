#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;
use ipc::signals;
use sandbox::events::ClosureWatcher;

struct ExitStateWatcher {
    expected: isize,
    triggered: bool
}

impl ExitStateWatcher {
    fn new(expected: isize) -> Self {
        ExitStateWatcher {expected: expected, triggered: false}
    }
}

impl sandbox::events::Watcher for ExitStateWatcher {
    fn notify_event(&mut self, event: &sandbox::events::Event) {
        match event.state {
            sandbox::events::State::Exit(st) => {
                assert!(st == self.expected);
                self.triggered = true;
            },
            _ => {}
        }
    }
}

impl Drop for ExitStateWatcher {
    fn drop(&mut self) {
        if !self.triggered {
            println!("Was not triggered");
        }
        assert!(self.triggered)
    }
}

#[test]
fn exec_bin_false() {
    let argv = ["/usr/bin/false"];
    let exec = sandbox::executors::Execv::new(&argv);
    let watch = ExitStateWatcher::new(1);
    sandbox::Sandbox::new(Box::new(exec), Box::new(watch)).exec();
}

#[test]
fn exec_bin_true() {
    let argv = ["/usr/bin/true"];
    let exec = sandbox::executors::Execv::new(&argv);
    let watch = ExitStateWatcher::new(0);
    sandbox::Sandbox::new(Box::new(exec), Box::new(watch)).exec();
}

#[test]
fn exec_closure() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
    let watch = ExitStateWatcher::new(0);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watch));
    sbox.exec();
}

#[test]
fn exec_closure_with_return() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {42}));
    let watch = ExitStateWatcher::new(42);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watch));
    sbox.exec();
}
