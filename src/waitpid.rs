#[allow(unstable)]
extern crate libc;
extern crate ptrace;
extern crate "posix-ipc" as ipc;

use self::ipc::signals;

use std::os;
use std::num::FromPrimitive;

#[derive(Copy, Show)]
pub enum WaitState {
    Stopped(signals::Signal),
    Continued,
    Exited(isize),
    Signaled(signals::Signal),
    PTrace(ptrace::Event)
}

impl WaitState {
    pub fn from_i32(v: i32) -> Self {
        if v & 0xff == 0x7f {
            let sig = FromPrimitive::from_i32((v & 0xff00) >> 8).expect("Unknown signal");
            let evt = ptrace::Event::from_wait_status(v);
            match evt {
                Option::Some(s) => WaitState::PTrace(s),
                Option::None => WaitState::Stopped(sig)
            }
        } else if v == 0xffff {
            WaitState::Continued
        } else if (v & 0xff00) >> 8 == 0 {
            WaitState::Exited((v & 0xff) as isize)
        } else if (((v & 0x7f) + 1) >> 1) > 0 {
            WaitState::Signaled(FromPrimitive::from_i32(v & 0x7f).expect("Unknown signal"))
        } else {
            panic! ("Unknown wait state: {:?}", v);
        }
    }
}

#[derive(Show, Copy)]
pub struct WaitResult {
    pub pid: libc::pid_t,
    pub status: i32,
    pub state: WaitState
}

bitflags! {
    flags Options: i32 {
        const None = 0,
        const NoWait = 1,
        const All = 0x40000000
    }
}

#[allow(unstable)]
pub fn wait(pid: libc::pid_t, opts: Options) -> Result<WaitResult, usize> {
    let mut st: libc::c_int = 0;
    let r;

    unsafe {
        r = ext::waitpid(pid, &mut st, opts.bits);
    }

    if r >= 0 {
        Result::Ok(WaitResult {pid: r, status: st, state: WaitState::from_i32(st)})
    } else {
        Result::Err(os::errno())
    }
}

mod ext {
    use super::libc;
    extern "C" {
        pub fn waitpid(pid: libc::pid_t, st: *mut libc::c_int, options: libc::c_int) -> libc::pid_t;
    }
}

#[cfg(test)]
mod test {
    extern crate libc;
    extern crate "posix-ipc" as ipc;
    extern crate ptrace;
    use std::thread::Thread;
    #[test]
    fn exit_wait() {
        let pid = unsafe {
            fork()
        };
        if pid == 0 {
            unsafe { libc::exit(0) };
        } else {
            let res = super::wait(pid, super::None).ok().expect("Could not wait on child");
            assert!(res.pid == pid);
            match res.state {
                super::WaitState::Exited(st) =>
                    assert!(st == 0),
                _ => panic!("Got a non-exit waitpid response")
            }
        }
    }

    #[test]
    fn bad_exit_wait() {
        let pid = unsafe {
            fork()
        };
        if pid == 0 {
            unsafe { libc::exit(1) };
        } else {
            let res = super::wait(pid, super::None).ok().expect("Could not wait on child");
            assert!(res.pid == pid);
            match res.state {
                super::WaitState::Exited(st) =>
                    assert!(st == 1),
                _ => panic!("Got a non-exit waitpid response")
            }
        }
    }

    #[test]
    fn killed_wait() {
        let pid = unsafe {
            fork()
        };

        if pid == 0 {
            ipc::signals::Signal::Kill.raise();
            unsafe { libc::exit(0) };
        } else {
            let res = super::wait(pid, super::None).ok().expect("Could not wait on child");
            assert!(res.pid == pid);
            match res.state {
                super::WaitState::Signaled(ipc::signals::Signal::Kill) => {},
                _ => panic!("Got a non-killed waitpid response")
            }
        }
    }

    #[test]
    fn ptrace_exit_wait() {
        let pid = unsafe {
            fork()
        };

        if pid == 0 {
            ipc::signals::Signal::Stop.raise();
            unsafe { libc::exit(0) };
        } else {
            ptrace::attach(pid).ok().expect("Could not attach to test process");
            super::wait(pid, super::None).ok().expect("Could not wait on child");
            ptrace::setoptions(pid, ptrace::TraceExit).ok().expect("Could not set options");
            ptrace::cont(pid, ipc::signals::Signal::None);
            super::wait(pid, super::None).ok().expect("Could not wait for child to resume");
            ptrace::cont(pid, ipc::signals::Signal::None);
            let res = super::wait(pid, super::None).ok().expect("Could not wait on child");
            assert!(res.pid == pid);
            match res.state {
                super::WaitState::PTrace(ptrace::Event::Exit) => {},
                _ => panic!("Got a non-ptrace-exit waitpid response")
            }
        }
    }

    extern "C" {
        fn fork() -> libc::pid_t;
    }

}
