#![allow(unstable)]
extern crate libc;
extern crate "posix-ipc" as ipc;
use self::ipc::signals;
use std::thread::Thread;
use executors;
use waitpid;

fn do_exec(mut exec: Box<executors::Executor>) -> Result<(), ()> {
    let pid = unsafe {
        fork()
    };

    if pid == 0 {
        exec.exec();
    } else {
        let r = waitpid::wait(pid, waitpid::None).ok().expect("Could not wait on child");
        println!("{:?}", r);
        match r.state {
            waitpid::WaitState::Exited(0) => Ok(()),
            _ => Err(())
        }
    }
}

#[test]
fn exec_bin_false() {
    let argv = ["/bin/true"];
    let exec: Box<executors::Executor> = Box::new(executors::Execv::new(&argv));
    do_exec(exec).ok().expect("Could not spawn /usr/bin/true");
}

#[test]
fn exec_bad_binary() {
    let argv = ["/this/shouldnt/be/a/binary"];
    let exec: Box<executors::Executor> = Box::new(executors::Execv::new(&argv));
    do_exec(exec).err().expect("Somehow spawned an imaginary binary");
}

#[test]
fn exec_closure() {
    let mut exec: Box<executors::Executor> = Box::new(executors::Function::new(Box::new(move |&:| -> i32 {0})));
    do_exec(exec).ok().expect("Could not spawn a closure");
}

extern "C" {
    fn fork() -> libc::pid_t;
}

