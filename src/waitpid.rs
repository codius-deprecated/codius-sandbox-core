extern crate libc;
extern crate "posix-ipc" as ipc;

use self::ipc::signals;

use std::os;
use std::num::FromPrimitive;

#[derive(Copy, Show)]
pub enum WaitState {
    Stopped(signals::Signal),
    Continued,
    Exited(isize),
    Signaled(signals::Signal)
}

impl WaitState {
    pub fn from_i32(v: i32) -> Self {
        if v & 0xff == 0x7f {
            WaitState::Stopped(FromPrimitive::from_i32((v & 0xff00) >> 8).expect("Unknown signal"))
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
