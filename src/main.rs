use strace::syscall;

use std::process::Command;
use std::os::unix::process::CommandExt;
use std::io::{Error as IoError, Result as IoResult};

use nix::sys::ptrace;
use nix::sys::wait::WaitStatus;

fn err_nix_to_io(err: nix::Error) -> IoError {
    match err {
        nix::Error::Sys(errno) => errno.into(),
        other => IoError::new(std::io::ErrorKind::Other, other),
    }
}

fn traceme() -> IoResult<()> {
    ptrace::traceme().map_err(err_nix_to_io)
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

    ptrace::setoptions(child_pid, ptrace::Options::empty()
        | ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_TRACECLONE
    ).expect("failed to call ptrace::setoptions");

    loop {
        let status = nix::sys::wait::waitpid(None, None)
            .map_err(err_nix_to_io).expect("failed to wait on tracee");
        println!("{:?}", status);
        match status {
            WaitStatus::Exited(pid, code) => {
                println!("+++ [{}] exited with {} +++", pid, code);
                if pid == child_pid {
                    break;
                } else {
                    continue;
                }
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
            WaitStatus::PtraceEvent(pid, _, _) => {
                println!("TODO event");
                ptrace::syscall(pid)
                    .map_err(err_nix_to_io).expect("failed to ask for a next syscall");
                continue;
            },
            /*
            WaitStatus::Stopped(pid, _) => {
                ptrace::syscall(pid).expect("failed to ask for a next syscall");
                continue;
            },
            */
            | WaitStatus::Stopped(pid, _)
            | WaitStatus::PtraceSyscall(pid) => {
                let regs = ptrace::getregs(pid).map_err(err_nix_to_io).expect("could not get regs");
                let syscall_id = regs.orig_rax as usize;

                syscall::name(syscall_id).map_or_else(|| {
                    println!("[{}]\tsyscall_{}\t{}\t{}\t{}", pid, syscall_id, regs.rdi, regs.rsi, regs.rax);
                }, |name| {
                    println!("[{}]\t{}\t{}\t{}\t{}", pid, name, regs.rdi, regs.rsi, regs.rax);
                });

                ptrace::syscall(pid).map_err(err_nix_to_io).expect("failed to ask for a next syscall");
                continue;
            },
        }
    }
}
