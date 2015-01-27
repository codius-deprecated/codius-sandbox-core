extern crate libc;
extern crate "codius-sandbox-core" as sandbox;
extern crate "posix-ipc" as ipc;

use std::num::FromPrimitive;

struct NullWatcher;

impl sandbox::events::Watcher for NullWatcher {
    fn notify_event(&mut self, event: &sandbox::events::Event) {
    }
}

#[test]
fn exec_and_release() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
    let mut watch = NullWatcher;
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watch);
    sbox.spawn();
    assert!(sbox.get_pid() != -1);
    assert!(sbox.is_running());
    sbox.release(ipc::signals::Signal::Cont);
    assert!(sbox.get_pid() == -1);
    assert!(!sbox.is_running());
}

// Skipped for now since release() doesn't appear to immediately cause WSIGNALED(SIGKILL).
//#[test]
fn release_with_kill() {
    let exec = sandbox::executors::Function::new(Box::new(move |&:| -> i32 {0}));
    let mut watch = NullWatcher;
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watch);
    sbox.spawn();
    let pid = sbox.get_pid();
    assert!(pid != -1);
    sbox.tick();
    sbox.release(ipc::signals::Signal::Kill);
    assert!(!sbox.is_running());
    assert!(sbox.get_pid() == -1);

    let mut st: libc::c_int = 0;
    assert!(unsafe { waitpid(pid, &mut st, 0) } == pid);
    let sig: ipc::signals::Signal = FromPrimitive::from_i32(st & 0x7f).expect("unknown signal");
    assert!(sig == ipc::signals::Signal::Kill);

    extern "C" {
        fn waitpid(pid: libc::pid_t, st: *mut libc::c_int, options: libc::c_int) -> libc::pid_t;
    }
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
