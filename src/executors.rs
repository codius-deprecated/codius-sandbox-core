#[allow(unstable)]
extern crate libc;
use std::ffi::CString;
use std::ptr;
use std::os;

pub trait Executor {
    fn exec(&mut self) -> !;
}

pub struct Execv<'a> {
    argv: &'a [&'a str]
}

impl<'a> Execv<'a> {
    pub fn new(argv: &'a [&'a str]) -> Self {
        Execv {
            argv: argv
        }
    }
}

impl<'a> Executor for Execv<'a> {
    #[allow(unstable)]
    fn exec(&mut self) -> ! {
        let command = CString::from_slice(self.argv[0].as_bytes());
        let mut ptrs: Vec<*const libc::c_char> = Vec::with_capacity(self.argv.len());
        for arg in self.argv.iter() {
            ptrs.push(CString::from_slice(arg.as_bytes()).as_ptr());
        }
        ptrs.push(ptr::null());

        let s;

        unsafe {
            s = libc::execvp(command.as_ptr(), ptrs.as_mut_ptr());
        }

        panic!("Could not exec {:?}: {:?} {:?}", self.argv, os::last_os_error(), os::errno());
    }
}

pub struct Function<'a> {
    closure: Box<Fn() -> i32 + 'a>
}

impl<'a> Function<'a> {
    pub fn new(closure: Box<Fn() -> i32 + 'a>) -> Self {
        Function {
            closure: closure
        }
    }
}

impl<'a> Executor for Function<'a> {
    fn exec(&mut self) -> ! {
        let ref c = self.closure;
        let st = c();
        unsafe { libc::exit(st) }
    }
}
