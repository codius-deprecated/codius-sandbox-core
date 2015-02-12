extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

#[test]
fn test_closure_watch() {
    let mut watcher_called = false;
    {
        let mut watcher = sandbox::events::ClosureWatcher::new(Box::new(|event: &sandbox::events::Event| {
            watcher_called = true;
        }));
        let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
        let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watcher);
        sbox.spawn();
        sbox.tick();
    }
    assert!(watcher_called);
}

#[test]
fn test_custom_watch() {
    struct Watch<'a> {
        hit: bool
    }
    impl<'a> sandbox::events::Watcher for Watch<'a> {
        fn notify_event(&mut self, event: &sandbox::events::Event) {
            self.hit = true;
        }
    }
    let mut watcher = Watch { hit: false };

    {
        let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
        let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watcher);
        sbox.spawn();
        sbox.tick();
    }

    assert!(watcher.hit);
}

// For some reason, this can hang.
//#[test]
fn test_event_cont() {
    struct Watch<'a> {
        hit: bool,
        sent_signal: ipc::signals::Signal
    }
    impl<'a> sandbox::events::Watcher for Watch<'a> {
        fn notify_event(&mut self, event: &sandbox::events::Event) {
            match event.state {
                sandbox::events::State::Signal(sig) => {
                    println!("Got signal {:?}", event);
                    self.sent_signal = sig;
                    event.cont();
                },
                _ => {println!("Unknown event {:?}", event);event.cont();}
            }
        }
    }
    let mut watcher = Watch { hit: false, sent_signal: ipc::signals::Signal::None };
    {
        let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {
            ipc::signals::Signal::Usr1.raise();
            loop {}
            0
        }));
        let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watcher);
        sbox.spawn();
        loop {
            if !sbox.is_running() {
                break
            }
            sbox.tick();
        }
    }
    assert!(watcher.sent_signal == ipc::signals::Signal::Usr1)
}
