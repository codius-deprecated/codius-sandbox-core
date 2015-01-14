#[allow(unstable)]
extern crate libc;
extern crate ptrace;
extern crate seccomp;
extern crate "posix-ipc" as ipc;

use executors::Executor;
use waitpid;
use events;

pub struct Sandbox<'a> {
    pid: libc::pid_t,
    executor: Box<Executor + 'a>
}

impl<'a> Sandbox<'a> {
    pub fn new(exec: Box<Executor + 'a>) -> Sandbox<'a> {
        Sandbox {
            pid: -1,
            executor: exec
        }
    }

    fn exec_child(&mut self) {
        ptrace::traceme();
        ipc::signals::Signal::Stop.raise().ok().expect("Could not stop child");

        self.setup_seccomp();
        self.executor.exec();
    }

    #[allow(unused_must_use)]
    fn setup_seccomp(&self) {
        let filter = seccomp::Filter::new(&seccomp::ACT_KILL).ok().expect("Could not allocate seccomp filter");
        let trace = seccomp::act_trace(0);

        // A duplicate in case the seccomp_init() call is accidentally modified
        filter.rule_add(&seccomp::ACT_KILL, seccomp::Syscall::PTRACE, &[]);

        // This is actually caught via PTRACE_EVENT_EXEC
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EXECVE, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::CLONE, &[]);

        // Use to track chdir calls
        filter.rule_add(&trace, seccomp::Syscall::CHDIR, &[]);
        filter.rule_add(&trace, seccomp::Syscall::FCHDIR, &[]);

        // These interact with the VFS layer
        filter.rule_add(&trace, seccomp::Syscall::OPEN, &[]);
        filter.rule_add(&trace, seccomp::Syscall::ACCESS, &[]);
        filter.rule_add(&trace, seccomp::Syscall::OPENAT, &[]);
        filter.rule_add(&trace, seccomp::Syscall::STAT, &[]);
        filter.rule_add(&trace, seccomp::Syscall::LSTAT, &[]);
        filter.rule_add(&trace, seccomp::Syscall::GETCWD, &[]);
        filter.rule_add(&trace, seccomp::Syscall::READLINK, &[]);

        macro_rules! vfs_filter(
          ($call:ident) => ({
            filter.rule_add(&trace, seccomp::Syscall::$call, &[
              seccomp::Compare::new(0, seccomp::Op::OpGe, 4098)
            ]);
            filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::$call, &[
              seccomp::Compare::new(0, seccomp::Op::OpLt, 4098)
            ]);
          });
        );


        vfs_filter!(READ);
        vfs_filter!(CLOSE);
        vfs_filter!(IOCTL);
        vfs_filter!(FSTAT);
        vfs_filter!(LSEEK);
        vfs_filter!(WRITE);
        vfs_filter!(GETDENTS);
        //vfs_filter!(READDIR);
        vfs_filter!(GETDENTS64);
        vfs_filter!(READV);
        vfs_filter!(WRITEV);

        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::FSYNC, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::FDATASYNC, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SYNC, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::POLL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::MMAP, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::MPROTECT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::MUNMAP, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::MADVISE, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::BRK, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::RT_SIGACTION, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::RT_SIGPROCMASK, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SELECT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SCHED_YIELD, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::GETPID, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::ACCEPT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::LISTEN, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EXIT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::GETTIMEOFDAY, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::TKILL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EPOLL_CREATE, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::RESTART_SYSCALL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::CLOCK_GETTIME, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::CLOCK_GETRES, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::CLOCK_NANOSLEEP, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::GETTID, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::IOCTL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::NANOSLEEP, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EXIT_GROUP, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EPOLL_WAIT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EPOLL_CTL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::TGKILL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::PSELECT6, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::PPOLL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::ARCH_PRCTL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::PRCTL, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SET_ROBUST_LIST, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::GET_ROBUST_LIST, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EPOLL_PWAIT, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::ACCEPT4, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EVENTFD2, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::EPOLL_CREATE1, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::PIPE2, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::FUTEX, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SET_TID_ADDRESS, &[]);
        filter.rule_add(&seccomp::ACT_ALLOW, seccomp::Syscall::SET_THREAD_AREA, &[]);

        filter.load().ok().expect("Could not load filter");
    }

    fn attach_to_child(&self) {
        ptrace::attach(self.pid).ok().expect("Could not attach.");
        let s = waitpid::wait(self.pid, waitpid::None);
        println!("attach: {:?}", s);
        s.ok().expect("Could not wait for child to enter ptrace");
        ptrace::setoptions(self.pid,
                           ptrace::TraceExit | ptrace::ExitKill |
                           ptrace::TraceSeccomp | ptrace::TraceExec |
                           ptrace::TraceClone).ok().expect("Could not set options");
        ptrace::cont(self.pid, ipc::signals::Signal::None).ok().expect("Could not continue");
        let s = waitpid::wait(self.pid, waitpid::None);
        println!("cont: {:?}", s);
    }

    pub fn tick(&mut self) -> events::Event {
        loop {
            let s = waitpid::wait(-self.pid, waitpid::NoWait | waitpid::All);
            println!("Got {:?}", s);
            let res = s.ok().expect("Could not wait on child");
            match res.state {
                waitpid::WaitState::Stopped(ipc::signals::Signal::Trap) => {
                    println!("Trapped");
                },
                _ => {println!("Unknown state {:?}", res);}
            }
            ptrace::cont(res.pid, ipc::signals::Signal::None);
        }
    }

    pub fn get_pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn release(&mut self, signal: ipc::signals::Signal) {
        ptrace::release(self.pid, signal);
        self.pid = -1;
    }

    pub fn spawn(&mut self) {
        self.pid = unsafe { fork() };
        match self.pid {
            0 => self.exec_child(),
            _ => self.attach_to_child()
        }
    }
}

extern "C" {
    fn fork() -> libc::pid_t;
}
