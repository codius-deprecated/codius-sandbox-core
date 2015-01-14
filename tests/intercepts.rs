#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

#[test]
fn intercept_exec() {
    unsafe {ipc::signals::Signal::Chld.handle(Box::new(|&:Signal| {println!("Child!");}))};
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    let mut exit_status;
    loop {
        let e = sbox.tick();
        println!("Event: {:?}", e);
        match e {
            sandbox::events::Event::Exit(st) => {
                exit_status = st;
                break;
            }
            _ => {}
        }
    }
    assert!(exit_status == 0);
}

