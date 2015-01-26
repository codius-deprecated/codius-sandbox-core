extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

struct NullWatcher;

impl sandbox::events::Watcher for NullWatcher {
    fn notify_event(&mut self, event: &sandbox::events::Event) {
    }
}

#[test]
fn release() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
    let watch = NullWatcher;
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), Box::new(watch));
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
    sbox.release(ipc::signals::Signal::Cont);
    assert!(sbox.get_pid() == -1);
}
