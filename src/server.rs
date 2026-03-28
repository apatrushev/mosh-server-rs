use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use nix::{
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    pty::{ForkptyResult, Winsize, forkpty},
    sys::{
        signal::{SigHandler, Signal, signal},
        wait::{WaitPidFlag, waitpid},
    },
    unistd::{close, execvp, pipe, read, write},
};

use crate::{
    network::{self, Connection},
    transport::{self, ServerTransport, UserAction},
};

pub fn run_server(
    desired_ip: Option<&str>,
    desired_port: Option<&str>,
    command: &[String],
    colors: i32,
    _verbose: bool,
    with_motd: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::new_server(desired_ip, desired_port)?;
    let port = connection.port()?;
    let key = connection.get_key();

    println!("\r\nMOSH CONNECT {} {}\r\n", port, key);

    unsafe {
        signal(Signal::SIGHUP, SigHandler::SigIgn).ok();
        signal(Signal::SIGPIPE, SigHandler::SigIgn).ok();
    }

    match unsafe { libc::fork() } {
        -1 => return Err("fork failed".into()),
        pid if pid > 0 => {
            eprintln!("[mosh-server detached, pid = {}]", pid);
            std::process::exit(0);
        }
        _ => {}
    }

    redirect_to_null();

    let ws = Winsize {
        ws_col: 80,
        ws_row: 24,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let (pipe_read, pipe_write) =
        pipe().map_err(|e| io::Error::other(format!("pipe: {}", e)))?;

    let fork_result = unsafe { forkpty(Some(&ws), None) }
        .map_err(|e| io::Error::other(format!("forkpty: {}", e)))?;

    match fork_result {
        ForkptyResult::Child => {
            let _ = close(pipe_write.as_raw_fd());

            unsafe {
                signal(Signal::SIGHUP, SigHandler::SigDfl).ok();
                signal(Signal::SIGPIPE, SigHandler::SigDfl).ok();
            }

            let term = if colors == 256 {
                "xterm-256color"
            } else {
                "xterm"
            };
            unsafe {
                std::env::set_var("TERM", term);
                std::env::set_var("NCURSES_NO_UTF8_ACS", "1");
                std::env::remove_var("STY");
            }

            #[cfg(target_os = "linux")]
            {
                use nix::sys::termios;
                if let Ok(mut attrs) = termios::tcgetattr(io::stdin()) {
                    attrs.input_flags.insert(termios::InputFlags::IUTF8);
                    let _ = termios::tcsetattr(
                        io::stdin(),
                        termios::SetArg::TCSANOW,
                        &attrs,
                    );
                }
            }

            if let Ok(home) = std::env::var("HOME") {
                let _ = std::env::set_current_dir(&home);
            }

            if with_motd {
                print_motd();
            }

            let mut buf = [0u8; 1];
            let pipe_fd = pipe_read.as_raw_fd();
            loop {
                match read(pipe_fd, &mut buf) {
                    Ok(_) => break,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }
            let _ = close(pipe_fd);

            let prog = CString::new(command[0].as_str()).expect("CString::new failed");
            let args: Vec<CString> = if command.len() > 1 {
                vec![CString::new(command[1].as_str()).expect("CString")]
            } else {
                vec![prog.clone()]
            };

            let _ = execvp(&prog, &args);
            eprintln!("execvp failed: {}", command[0]);
            std::process::exit(1);
        }
        ForkptyResult::Parent { child, master } => {
            let _ = close(pipe_read.as_raw_fd());
            let _ = close(pipe_write.as_raw_fd());
            let transport = ServerTransport::new(connection);
            serve(master.as_raw_fd(), child, transport)?;
            let _ = close(master.as_raw_fd());
        }
    }

    Ok(())
}

fn serve(
    host_fd: i32,
    child: nix::unistd::Pid,
    mut transport: ServerTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_remote_num: u64 = 0;
    let timeout_no_client: u64 = 60000;
    let mut child_exited = false;
    let startup_time = network::timestamp();

    loop {
        let mut timeout = transport.wait_time().min(5000);
        if transport.get_remote_state_num() == 0 {
            timeout = timeout.min(5000);
        }

        let net_fd = transport.connection().socket_fd().as_raw_fd();
        let net_bfd = unsafe { BorrowedFd::borrow_raw(net_fd) };
        let host_bfd = unsafe { BorrowedFd::borrow_raw(host_fd) };

        let mut poll_fds = vec![
            PollFd::new(net_bfd, PollFlags::POLLIN),
            PollFd::new(host_bfd, PollFlags::POLLIN),
        ];

        if transport.shutdown_in_progress() {
            poll_fds.pop();
        }

        let poll_timeout = if timeout == u64::MAX {
            PollTimeout::NONE
        } else {
            PollTimeout::try_from(timeout as i32).unwrap_or(PollTimeout::NONE)
        };
        let _ = poll(&mut poll_fds, poll_timeout);

        let now = network::timestamp();
        let mut terminal_to_host = Vec::<u8>::new();

        if poll_fds[0]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            match transport.recv() {
                Ok(Some(diff)) => {
                    let remote_num = transport.get_remote_state_num();
                    if remote_num != last_remote_num {
                        last_remote_num = remote_num;

                        let actions = transport::parse_user_actions(&diff);

                        for action in &actions {
                            match action {
                                UserAction::Keystroke(keys) => {
                                    terminal_to_host.extend_from_slice(keys);
                                }
                                UserAction::Resize(w, h) => {
                                    let mut ws: libc::winsize =
                                        unsafe { std::mem::zeroed() };
                                    ws.ws_col = *w as u16;
                                    ws.ws_row = *h as u16;
                                    unsafe {
                                        libc::ioctl(host_fd, libc::TIOCSWINSZ, &ws);
                                    }
                                    transport.set_pending_resize(*w, *h);
                                }
                            }
                        }

                        if !actions.is_empty() {
                            transport.register_input_frame(remote_num, now);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    log::debug!("recv error: {}", e);
                }
            }
        }

        if !terminal_to_host.is_empty() {
            let host_bfd = unsafe { BorrowedFd::borrow_raw(host_fd) };
            if write(host_bfd, &terminal_to_host).is_err() {
                transport.start_shutdown();
            }
        }

        let echo_ack_changed = transport.update_echo_ack(now);
        if echo_ack_changed && transport.echo_ack() > 0 {
            transport.set_pending_echo_ack(transport.echo_ack());
        }

        if !transport.shutdown_in_progress() && poll_fds.len() > 1 {
            let revents = poll_fds[1].revents().unwrap_or(PollFlags::empty());
            if revents.intersects(PollFlags::POLLIN) {
                let mut buf = [0u8; 16384];
                match read(host_fd, &mut buf) {
                    Ok(0) | Err(_) => {
                        transport.start_shutdown();
                    }
                    Ok(n) => {
                        transport.push_output(&buf[..n]);
                    }
                }
            } else if revents.intersects(PollFlags::POLLHUP | PollFlags::POLLERR) {
                transport.start_shutdown();
            }
        }

        if !child_exited
            && !transport.shutdown_in_progress()
            && let Ok(
                nix::sys::wait::WaitStatus::Exited(..)
                | nix::sys::wait::WaitStatus::Signaled(..),
            ) = waitpid(child, Some(WaitPidFlag::WNOHANG))
        {
            child_exited = true;
            transport.start_shutdown();
        }

        if transport.get_remote_state_num() == 0
            && now.saturating_sub(startup_time) >= timeout_no_client
        {
            eprintln!("No connection within {} seconds.", timeout_no_client / 1000);
            break;
        }

        if transport.shutdown_in_progress() && transport.shutdown_acknowledged() {
            break;
        }
        if transport.shutdown_in_progress() && transport.shutdown_ack_timed_out() {
            break;
        }
        if transport.counterparty_shutdown_ack_sent() {
            transport.tick()?;
            break;
        }

        transport.tick()?;
    }

    eprintln!("[mosh-server is exiting.]");
    Ok(())
}

fn print_motd() {
    if std::path::Path::new(".hushlogin").exists() {
        return;
    }
    if !print_motd_file("/run/motd.dynamic") {
        print_motd_file("/var/run/motd.dynamic");
    }
    print_motd_file("/etc/motd");
}

fn print_motd_file(path: &str) -> bool {
    let Ok(contents) = std::fs::read(path) else {
        return false;
    };
    if contents.is_empty() {
        return false;
    }
    use std::io::Write;
    std::io::stdout().write_all(&contents).is_ok()
}

fn redirect_to_null() {
    unsafe {
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if fd >= 0 {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
    }
}
