use std::{env, process};

mod proto {
    pub mod transport_buffers {
        include!(concat!(env!("OUT_DIR"), "/transport_buffers.rs"));
    }
    pub mod host_buffers {
        include!(concat!(env!("OUT_DIR"), "/host_buffers.rs"));
    }
    pub mod client_buffers {
        include!(concat!(env!("OUT_DIR"), "/client_buffers.rs"));
    }
}

mod crypto;
mod network;
mod server;
mod transport;

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    let mut desired_ip: Option<String> = None;
    let mut desired_port: Option<String> = None;
    let mut colors: i32 = 0;
    let mut verbose = false;
    let mut command_argv: Option<Vec<String>> = None;
    let mut use_ssh_ip = false;

    let mut i = 1;
    if i < args.len() && args[i] == "new" {
        i += 1;
    }

    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                if i + 1 < args.len() {
                    command_argv = Some(args[i + 1..].to_vec());
                }
                break;
            }
            "-i" => {
                i += 1;
                if i < args.len() {
                    desired_ip = Some(args[i].clone());
                }
            }
            "-p" => {
                i += 1;
                if i < args.len() {
                    desired_port = Some(args[i].clone());
                }
            }
            "-c" => {
                i += 1;
                if i < args.len() {
                    colors = args[i].parse().unwrap_or(0);
                }
            }
            "-s" => {
                use_ssh_ip = true;
            }
            "-v" => {
                verbose = true;
            }
            _ => {}
        }
        i += 1;
    }

    if use_ssh_ip {
        desired_ip = get_ssh_ip();
    }

    let (command, with_motd) = if let Some(argv) = command_argv {
        (argv, false)
    } else {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let shell_name = shell.rsplit('/').next().unwrap_or("sh");
        let login_shell = format!("-{}", shell_name);
        (vec![shell, login_shell], true)
    };

    match server::run_server(
        desired_ip.as_deref(),
        desired_port.as_deref(),
        &command,
        colors,
        verbose,
        with_motd,
    ) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("mosh-server error: {}", e);
            process::exit(1);
        }
    }
}

fn get_ssh_ip() -> Option<String> {
    env::var("SSH_CONNECTION").ok().and_then(|conn| {
        let parts: Vec<&str> = conn.split_whitespace().collect();
        if parts.len() >= 3 {
            let mut ip = parts[2].to_string();
            if let Some(stripped) = ip.strip_prefix("::ffff:") {
                ip = stripped.to_string();
            }
            Some(ip)
        } else {
            None
        }
    })
}
