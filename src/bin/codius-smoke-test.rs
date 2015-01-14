extern crate "codius-sandbox-core" as sandbox;

#[main]
fn main() {
    let argv = ["/usr/bin/true"];
    let exec = sandbox::executors::Execv::new(&argv);
    let mut sbox = sandbox::Sandbox::new(Box::new(exec));
    sbox.spawn();
    loop {
        let e = sbox.tick();
        match e {
            sandbox::events::Event::Exit(st) => {
                println!("Child exited with {:?}", st);
                break;
            },
            sandbox::events::Event::Signal(s) => {
                println!("Got signal {:?}", s);
            },
            sandbox::events::Event::None => {},
            _ => {
                panic!("Unhandled sandbox event {:?}", e);
            }
        }
    }
}
