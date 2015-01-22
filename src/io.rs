#[allow(unstable)]
extern crate core;

use std::io::IoResult;

pub trait Handle {
    fn get_local_fd(&self) -> i32;
    fn get_virt_fd(&self) -> i32;
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize>;
    fn write(&mut self, buf: &[u8]) -> IoResult<usize>;
    fn close(&mut self) -> IoResult<()>;
}

pub trait Streaming {
    fn do_write(&mut self, handle: &Handle, buf: &[u8]) -> IoResult<usize>;
    fn do_read(&mut self, handle: &Handle, buf: &mut [u8]) -> IoResult<usize>;
    fn do_close(&mut self, handle: &Handle) -> IoResult<()>;
}
