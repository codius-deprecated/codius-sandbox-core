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
    executor: Box<Executor + 'a>,
    entered_main: bool
}

impl<'a> Sandbox<'a> {
    pub fn new(exec: Box<Executor + 'a>) -> Sandbox<'a> {
        Sandbox {
            pid: -1,
            executor: exec,
            entered_main: false
        }
    }

    fn exec_child(&mut self) {
        extern "C" { fn clearenv(); fn setpgid(a: libc::c_int, b: libc::c_int); };
        unsafe {
            clearenv(); 
            setpgid(0, 0);
        }
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
        println!("post attach: {:?}", s);
        s.ok().expect("Could not wait for child to enter ptrace");
        ptrace::setoptions(self.pid,
                           ptrace::TraceExit | ptrace::ExitKill |
                           ptrace::TraceSeccomp | ptrace::TraceExec |
                           ptrace::TraceClone).ok().expect("Could not set options");
        ptrace::cont(self.pid, ipc::signals::Signal::None).ok().expect("Could not continue");
    }

    fn handle_exec(&mut self, res: waitpid::WaitResult) -> events::Event {
        if (!self.entered_main) {
            self.entered_main = true;
            return events::Event::EnteredMain
        } else {
            return self.release(ipc::signals::Signal::Kill);
        }
    }

    pub fn tick(&mut self) -> events::Event {
        assert!(self.pid > 0);
        let s = waitpid::wait(-1, waitpid::All);
        let res = s.ok().expect("Could not wait on child");
        if res.pid == 0 && res.status == 0 {
            return events::Event::None;
        }
        match res.state {
            waitpid::WaitState::PTrace(e) =>
                match e {
                    ptrace::Event::Exec => return self.handle_exec(res),
                    _ => panic!("Unhandled ptrace event {:?}", res)
                },
            waitpid::WaitState::Stopped(s) => {
                ptrace::cont(res.pid, s);
                return events::Event::Signal(s);
            },
            waitpid::WaitState::Exited(st) => {
                self.release(ipc::signals::Signal::None);
                return events::Event::Exit(st);
            }
            _ => panic!("Unknown state {:?}", res)
        }
    }

    pub fn get_pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn release(&mut self, signal: ipc::signals::Signal) -> events::Event {
        ptrace::release(self.pid, signal);
        self.pid = -1;
        return events::Event::Released(signal);
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
