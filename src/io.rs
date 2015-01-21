pub struct Handle<'a> {
    local_fd: isize,
    virt_fd: isize,
    handler: &'a (Streaming + 'a)
}

impl<'a> Handle<'a> {
    pub fn new(handler: &'a (Streaming + 'a), local_fd: isize) -> Self {
        Handle {
            local_fd: local_fd,
            virt_fd: -1,
            handler: handler
        }
    }
}

pub trait Streaming {
    fn do_write(&mut self, handle: &Handle, buf: &[u8]) -> isize;
    fn do_read(&mut self, handle: &Handle, buf: &[u8]) -> isize;
    fn do_close(&mut self, handle: &Handle);
}
