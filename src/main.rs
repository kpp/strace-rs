use std::process::Command;
use std::os::unix::process::CommandExt;
use std::io::{Error as IoError, Result as IoResult};

use nix::sys::ptrace;
use nix::sys::wait::WaitStatus;

fn traceme() -> IoResult<()> {
    ptrace::traceme()
        .map_err(|e| {
            match e {
                nix::Error::Sys(errno) => errno.into(),
                other => IoError::new(std::io::ErrorKind::Other, other),
            }
        })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let prog_name = args.next().expect("must have PROG [ARGS]");
    let child = unsafe {
        Command::new(prog_name)
            .args(args)
            .pre_exec(traceme)
            .spawn()
            .expect("failed to start tracee")
    };

    let child_pid = nix::unistd::Pid::from_raw(child.id() as _);

    ptrace::setoptions(child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXEC
    ).expect("failed to call ptrace::setoptions");

    loop {
        let status = nix::sys::wait::waitpid(child_pid, None).expect("failed to wait on tracee");
        println!("{:?}", status);
        match status {
            WaitStatus::Exited(_, _) => {
                break;
            },
            WaitStatus::Signaled(_, _, _) => {
                break;
            },
            WaitStatus::Continued(_) => {
                break;
            },
            WaitStatus::StillAlive => {
                break;
            },
            WaitStatus::PtraceEvent(_, _, _) => {
                println!("TODO event");
                break;
            },
            WaitStatus::Stopped(pid, _) => {
                ptrace::syscall(pid).expect("failed to ask for a next syscall");
                continue;
            },
            | WaitStatus::PtraceSyscall(pid) => {
                let regs = ptrace::getregs(pid).expect("could not get regs");
                println!("\trip: {:x}", regs.rip);
                println!("\trbp: {:x}", regs.rbp);
                println!("\trsp: {:x}", regs.rsp);
                println!("\trax: {:x}", regs.rax);
                println!("\trcx: {:x}", regs.rcx);
                println!("\trdx: {:x}", regs.rdx);

                ptrace::syscall(pid).expect("failed to ask for a next syscall");
                continue;
            },
        }
    }
}
