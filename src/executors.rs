#[allow(unstable)]
extern crate libc;
use std::ffi::CString;
use std::ptr;

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
        let mut ptrs: Vec<*const libc::c_char> = Vec::with_capacity(self.argv.len());
        for arg in self.argv.iter() {
            ptrs.push(CString::from_slice(arg.as_bytes()).as_ptr());
        }
        ptrs.push(ptr::null());

        unsafe {
            libc::execvp(ptrs[0], ptrs.as_mut_ptr());
        }

        panic!("Could not exec {:?}", self.argv);
    }
}

pub struct Function<'a> {
    closure: Box<Fn() + 'a>
}

impl<'a> Function<'a> {
    pub fn new(closure: Box<Fn() + 'a>) -> Self {
        Function {
            closure: closure
        }
    }
}

impl<'a> Executor for Function<'a> {
    fn exec(&mut self) -> ! {
        let ref c = self.closure;
        c();
        panic! ("Closure should not return!");
    }
}
