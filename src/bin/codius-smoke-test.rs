#![allow(unstable)]
extern crate "codius-sandbox-core" as sandbox;
extern crate seccomp;
extern crate ptrace;
#[macro_use]
extern crate log;

use std::os;
use std::str;
use sandbox::events;
use sandbox::vfs;

struct NullWatcher;

impl sandbox::events::Watcher for NullWatcher {
    fn notify_event(&mut self, event: &events::Event) {
        event.cont();
    }
}

struct PrintLogger;

impl log::Log for PrintLogger {
    fn enabled(&self, level: log::LogLevel, _module: &str) -> bool {
        level <= log::LogLevel::Trace
    }

    fn log(&self, record: &log::LogRecord) {
        if self.enabled(record.level(), record.location().module_path) {
            println!("{}: {}", record.level(), record.args());
        }
    }
}

fn main() {
    log::set_logger(|max_log_level| {
        max_log_level.set(log::LogLevelFilter::Trace);
        Box::new(PrintLogger)
    });
    let args = os::args();
    let mut argv = Vec::new();
    let mut i = args.iter();
    i.next();
    for arg in i {
        argv.push(str::from_utf8(arg.as_bytes()).ok().expect("Invalid argv"));
    }
    let exec = sandbox::executors::Execv::new(argv.as_slice());
    let mut watcher = PrintWatcher {vfs: vfs::VFS::new()};
    watcher.vfs.mount_filesystem("/", Box::new(vfs::native::NativeFS::new(Path::new("/"))));
    let mut sbox = sandbox::Sandbox::new(Box::new(exec), &mut watcher);
    sbox.spawn();
    loop {
        if !sbox.is_running() {
            break
        }
        sbox.tick();
    }
}

struct PrintWatcher<'a> {
    vfs: vfs::VFS<'a>
}

impl<'a> events::Watcher for PrintWatcher<'a> {
    fn notify_event(&mut self, event: &events::Event) {
        match event.state {
            events::State::Exit(st) => {
                info!("Child exited with {:?}", st);
                event.cont();
            },
            events::State::EnteredMain => {
                info!("Child has entered main()");
                event.cont();
            },
            events::State::Signal(s) => {
                info!("Got signal {:?}", s);
                event.cont();
            },
            events::State::Seccomp(_) => {
                let mut e = events::Syscall::from_event(*event).expect("Not a syscall?");
                (&mut self.vfs as &mut events::SyscallHandler).handle_syscall(&mut e);
            },
            events::State::None => {},
            _ => {
                panic!("Unhandled sandbox event {:?}", event);
            }
        }
    }
}
