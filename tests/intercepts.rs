#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

#[test]
fn intercept_exec() {
    unsafe {ipc::signals::Signal::Chld.handle(Box::new(|&:Signal| {println!("Child!");}))};
    let exec = sandbox::executors::Function::new(Box::new(move |&:| {}));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    loop {
        let e = sbox.tick();
        println!("Event: {:?}", e);
    }
}

