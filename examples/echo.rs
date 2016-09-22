extern crate nix;
extern crate getopts;
extern crate memfd;

use std::io;
use std::os::unix::io::{RawFd, AsRawFd};
use std::path::{Path, PathBuf};

use nix::sys::socket::*;
use nix::unistd::*;
use nix::sys::uio::*;

use getopts::Options;
use std::env;

use memfd::*;

#[derive(Debug)]
pub struct UnixDatagram {
    fd: RawFd,
}

impl UnixDatagram {
    pub fn new() -> io::Result<UnixDatagram> {
        let fd = match socket(AddressFamily::Unix, SockType::Datagram, SOCK_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        Ok(UnixDatagram { fd: fd })
    }

    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<UnixDatagram> {
        let datagram = try!(UnixDatagram::new());

        let _ = unlink(path.as_ref());

        let addr = match UnixAddr::new(path.as_ref()) {
            Ok(addr) => addr,
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        match bind(datagram.fd, &SockAddr::Unix(addr)) {
            Ok(()) => (),
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        Ok(datagram)
    }

    pub fn send<P: AsRef<Path>>(&self,
                                path: P,
                                data: &[u8],
                                memfd: Option<&SealedMemFd>)
                                -> io::Result<()> {
        let iov = [IoVec::from_slice(data)];
        let addr = match UnixAddr::new(path.as_ref()) {
            Ok(addr) => addr,
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        let res = match memfd {
            Some(fd) => {
                sendmsg(self.fd,
                        &iov,
                        &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
                        MSG_CMSG_CLOEXEC,
                        Some(&SockAddr::Unix(addr)))
            }
            None => {
                sendmsg(self.fd,
                        &iov,
                        &[],
                        MsgFlags::empty(),
                        Some(&SockAddr::Unix(addr)))
            }
        };

        match res {
            Ok(_) => Ok(()),
            Err(nix::Error::Sys(errno)) => Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        }
    }

    pub fn recv(&self,
                data: &mut [u8],
                memfd: &mut Option<SealedMemFd>)
                -> io::Result<(usize, Option<PathBuf>)> {
        let iov = [IoVec::from_mut_slice(data)];
        let mut cmsgs: CmsgSpace<[RawFd; 1]> = CmsgSpace::new();

        let msg = match recvmsg(self.fd, &iov, Some(&mut cmsgs), MSG_CMSG_CLOEXEC) {
            Ok(msg) => msg,
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        let path = msg.address
            .map(|a| {
                match a {
                    SockAddr::Unix(u) => u.path().map(|p| p.to_path_buf()),
                    _ => None,
                }
            })
            .and_then(|p| p);

        *memfd = None;
        for cmsg in msg.cmsgs() {
            match cmsg {
                ControlMessage::ScmRights(fds) if fds.len() == 1 => {
                    *memfd = Some(try!(SealedMemFd::new(fds[0])));
                    break;
                }
                _ => (),
            };
        }

        Ok((msg.bytes, path))
    }
}

impl Drop for UnixDatagram {
    fn drop(&mut self) {
        if self.fd != -1 {
            let _ = close(self.fd);
        }
    }
}

fn run_server<P: AsRef<Path>>(path: P) {
    let dg = UnixDatagram::bind(path).unwrap();

    loop {
        let mut data = [0; 1024];
        let mut memfd = None;
        let res = dg.recv(&mut data, &mut memfd).unwrap();

        let memfd = memfd.unwrap();

        println!("Received {} bytes from {:?}", res.0, res.1);
        println!("Data: {:?}", &data[0..res.0]);
        println!("MemFd size: {}", memfd.get_size().unwrap());
        // println!("MemFd data: {:?}", memfd.as_slice());
        println!("");
    }
}

fn run_client<P: AsRef<Path>>(path: P) {
    let dg = UnixDatagram::new().unwrap();
    let path_ref = path.as_ref();

    loop {
        let data = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut mfd = MemFd::new("echo").unwrap();
        let _ = mfd.set_size(1024 * 1024).unwrap();

        {
            let s = mfd.as_mut_slice().unwrap();
            for i in 0..s.len() {
                s[i] = i as u8;
            }
        }

        let smfd = mfd.seal().unwrap();

        let res = dg.send(path_ref, &data, Some(&smfd));
        println!("Sent: {:?}", res);
        res.unwrap();
    }
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Help");
    opts.optflag("c", "client", "Run in client mode");
    opts.optflag("s", "server", "Run in server mode");
    opts.reqopt("p", "path", "Path to connect to", "PATH");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };

    if matches.opt_present("h") {
        print_usage(&program, &opts);
        return;
    }

    if matches.opt_present("c") && matches.opt_present("s") {
        print_usage(&program, &opts);
        return;
    }

    let path = match matches.opt_str("p") {
        Some(path) => path,
        None => {
            print_usage(&program, &opts);
            return;
        }
    };

    if matches.opt_present("c") {
        run_client(&path);
    } else if matches.opt_present("s") {
        run_server(&path);
    } else {
        print_usage(&program, &opts);
        return;
    }
}
