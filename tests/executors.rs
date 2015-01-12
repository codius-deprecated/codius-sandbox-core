#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;

#[test]
fn exec_bin_true() {
    let argv = ["/usr/bin/true"];
    let exec = sandbox::executors::Execv::new(&argv);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.exec();
}

#[test]
fn exec_closure() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| {}));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.exec();
}
