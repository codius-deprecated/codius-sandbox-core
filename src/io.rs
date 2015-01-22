extern crate core;

use std::cell::RefCell;
use std::rc::Rc;
use std::io::IoResult;

pub trait Handle {
    fn get_local_fd(&self) -> i32;
    fn get_virt_fd(&self) -> i32;
    fn read(&self, buf: &mut [u8]) -> IoResult<isize>;
    fn write(&mut self, buf: &[u8]) -> IoResult<isize>;
    fn close(&mut self) -> IoResult<()>;
}

pub trait Streaming {
    fn do_write(&mut self, handle: &Handle, buf: &[u8]) -> IoResult<isize>;
    fn do_read(&self, handle: &Handle, buf: &mut [u8]) -> IoResult<isize>;
    fn do_close(&mut self, handle: &Handle) -> IoResult<()>;
}
