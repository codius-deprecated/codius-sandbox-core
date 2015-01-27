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
    let mut watch = NullWatcher;
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watch);
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
    sbox.release(ipc::signals::Signal::Cont);
    assert!(sbox.get_pid() == -1);
}

struct ExitStateWatcher {
    expected: isize,
    triggered: bool
}

impl ExitStateWatcher {
    fn new(expected: isize) -> Self {
        ExitStateWatcher {expected: expected, triggered: false}
    }

    fn assert_triggered(&self) {
        assert!(self.triggered);
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
