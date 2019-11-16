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

    ptrace::setoptions(child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEEXEC
    ).expect("failed to call ptrace::setoptions");

    loop {
        let status = nix::sys::wait::waitpid(child_pid, None)
            .map_err(err_nix_to_io).expect("failed to wait on tracee");
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
            /*
            WaitStatus::Stopped(pid, _) => {
                ptrace::syscall(pid).expect("failed to ask for a next syscall");
                continue;
            },
            */
            | WaitStatus::Stopped(pid, _)
            | WaitStatus::PtraceSyscall(pid) => {
                let regs = ptrace::getregs(pid).map_err(err_nix_to_io).expect("could not get regs");

                // https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
                println!("\t\t\trdi\trsi\trax");
                println!("\tsyscall_{}\t{}\t{}\t{}", regs.orig_rax, regs.rdi, regs.rsi, regs.rax);

                ptrace::syscall(pid).map_err(err_nix_to_io).expect("failed to ask for a next syscall");
                continue;
            },
        }
    }
}
