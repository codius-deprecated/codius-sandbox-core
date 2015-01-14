#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;
use ipc::signals;

#[test]
fn exec_bin_true() {
    let argv = ["/usr/bin/true"];
    let exec = sandbox::executors::Execv::new(&argv);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
}

#[test]
fn exec_closure() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| {}));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
}

#[test]
fn release() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| {}));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
    sbox.release(ipc::signals::Signal::Cont);
    assert!(sbox.get_pid() == -1);
}
