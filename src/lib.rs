extern crate nix;
extern crate libc;

use libc::{off_t, c_void, size_t};
use nix::sys::stat::*;
use nix::fcntl::*;
use nix::sys::memfd::*;
use nix::unistd::*;
use nix::sys::mman::*;
use std::ptr;
use std::slice;
use std::io;
use std::ffi::CString;
use std::os::unix::io::{RawFd, IntoRawFd, AsRawFd};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        MemFd::new("test").unwrap();
    }

    #[test]
    fn test_set_get_size() {
        let mut mfd = MemFd::new("test").unwrap();
        assert_eq!(mfd.get_size().unwrap(), 0);
        mfd.set_size(1024).unwrap();
        assert_eq!(mfd.get_size().unwrap(), 1024);
    }

    #[test]
    fn test_shrink() {
        let mut mfd = MemFd::new("test").unwrap();
        mfd.set_size(1024).unwrap();
        mfd.set_size(512).unwrap();
        assert_eq!(mfd.get_size().unwrap(), 512);
    }

    #[test]
    fn test_grow() {
        let mut mfd = MemFd::new("test").unwrap();
        mfd.set_size(1024).unwrap();
        mfd.set_size(2048).unwrap();
        assert_eq!(mfd.get_size().unwrap(), 2048);
    }

    #[test]
    fn test_as_slice() {
        let mut mfd = MemFd::new("test").unwrap();
        mfd.set_size(1024).unwrap();

        let s = mfd.as_slice().unwrap();
        assert_eq!(s.len(), 1024);
    }

    #[test]
    fn test_as_mut_slice() {
        let mut mfd = MemFd::new("test").unwrap();
        mfd.set_size(1024).unwrap();

        let s = mfd.as_mut_slice().unwrap();
        assert_eq!(s.len(), 1024);
    }

    #[test]
    fn test_seal() {
        let mut mfd = MemFd::new("test").unwrap();
        mfd.set_size(1024).unwrap();

        {
            let s = mfd.as_mut_slice().unwrap();
            assert_eq!(s.len(), 1024);
            s[0] = 12u8;
        }

        let smfd = mfd.seal().unwrap();
        assert_eq!(smfd.get_size().unwrap(), 1024);

        {
            let s = smfd.as_slice().unwrap();
            assert_eq!(s.len(), 1024);
            assert_eq!(s[0], 12u8);
        }
        assert_eq!(smfd.get_size().unwrap(), 1024);
    }

    #[test]
    fn test_clone() {
        let clone = {
            let mut mfd = MemFd::new("test").unwrap();
            mfd.set_size(1024).unwrap();

            {
                let s = mfd.as_mut_slice().unwrap();
                assert_eq!(s.len(), 1024);
                s[0] = 12u8;
            }

            let smfd = mfd.seal().unwrap();

            {
                let s = smfd.as_slice().unwrap();
                assert_eq!(s.len(), 1024);
                assert_eq!(s[0], 12u8);
            }

            smfd.clone().unwrap()
        };

        {
            let s = clone.as_slice().unwrap();
            assert_eq!(s.len(), 1024);
            assert_eq!(s[0], 12u8);
        }
    }
}

#[derive(Debug)]
enum Map {
    Unmapped,
    ReadWrite(*mut c_void, usize),
}

#[derive(Debug)]
pub struct MemFd {
    fd: RawFd,
    map: Map,
}

#[derive(Debug)]
enum SealedMap {
    Unmapped,
    ReadOnly(*mut c_void, usize),
}

#[derive(Debug)]
pub struct SealedMemFd {
    fd: RawFd,
    map: SealedMap,
}

impl MemFd {
    pub fn new<T: Into<Vec<u8>>>(name: T) -> Result<MemFd, io::Error> {
        let c_name = try!(CString::new(name.into())
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid name")));

        let fd = match memfd_create(&c_name, MFD_ALLOW_SEALING | MFD_CLOEXEC) {
            Ok(fd) => fd,
            Err(nix::Error::Sys(errno)) => {
                return Err(io::Error::from_raw_os_error(errno as i32));
            }
            Err(_) => unreachable!(),
        };

        let memfd = MemFd {
            fd: fd,
            map: Map::Unmapped,
        };

        try!(memfd.ensure_seals());

        Ok(memfd)
    }

    pub unsafe fn new_from_fd(fd: RawFd) -> Result<MemFd, io::Error> {
        let mut memfd = MemFd {
            fd: fd,
            map: Map::Unmapped,
        };

        try!(memfd.ensure_seals());
        try!(memfd.update_map());

        Ok(memfd)
    }

    fn ensure_seals(&self) -> Result<(), io::Error> {
        match fcntl(self.fd, FcntlArg::F_GET_SEALS) {
            Ok(seals) if SealFlag::from_bits_truncate(seals).is_empty() => Ok(()),
            Ok(seals) => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                   format!("memfd is sealed: {:?}",
                                           SealFlag::from_bits_truncate(seals))))
            }
            Err(nix::Error::Sys(errno)) => Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        }
    }

    pub fn set_size(&mut self, size: usize) -> Result<(), io::Error> {
        try!(self.ensure_seals());

        match ftruncate(self.fd, size as off_t) {
            Ok(_) => (),
            Err(nix::Error::Sys(errno)) => return Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        };

        try!(self.update_map());

        Ok(())
    }

    fn unmap(&mut self) -> Result<(), io::Error> {
        match self.map {
            Map::ReadWrite(p, size) => {
                match munmap(p, size) {
                    Ok(_) => {
                        self.map = Map::Unmapped;
                        Ok(())
                    }
                    Err(nix::Error::Sys(errno)) => {
                        self.map = Map::Unmapped;
                        Err(io::Error::from_raw_os_error(errno as i32))
                    }
                    Err(_) => unreachable!(),
                }
            }
            Map::Unmapped => Ok(()),
        }
    }

    fn update_map(&mut self) -> Result<(), io::Error> {
        try!(self.unmap());
        try!(self.ensure_seals());

        let size = try!(self.get_size());

        let p = match mmap(ptr::null_mut(),
                           size as size_t,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED,
                           self.fd,
                           0) {
            Ok(p) => p,
            Err(nix::Error::Sys(errno)) => return Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        };

        self.map = Map::ReadWrite(p, size);

        Ok(())
    }

    pub fn get_size(&self) -> Result<usize, io::Error> {
        match fstat(self.fd) {
            Ok(stat) => Ok(stat.st_size as usize),
            Err(nix::Error::Sys(errno)) => Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        }
    }

    pub fn as_slice<'a>(&'a self) -> Result<&'a [u8], io::Error> {
        let size = try!(self.get_size());
        if size == 0 {
            return Ok(&[]);
        }

        match self.map {
            Map::Unmapped => Err(io::Error::new(io::ErrorKind::PermissionDenied, "unmapped")),
            Map::ReadWrite(p, s) => Ok(unsafe { slice::from_raw_parts(p as *const u8, s) }),
        }
    }

    pub fn as_mut_slice<'a>(&'a mut self) -> Result<&'a mut [u8], io::Error> {
        let size = try!(self.get_size());
        if size == 0 {
            return Ok(&mut []);
        }
        match self.map {
            Map::Unmapped => Err(io::Error::new(io::ErrorKind::PermissionDenied, "unmapped")),
            Map::ReadWrite(p, s) => Ok(unsafe { slice::from_raw_parts_mut(p as *mut u8, s) }),
        }
    }

    pub fn seal(mut self) -> Result<SealedMemFd, io::Error> {
        let fd = self.fd;
        try!(self.unmap());
        self.fd = -1;

        match fcntl(fd,
                    FcntlArg::F_ADD_SEALS(F_SEAL_GROW | F_SEAL_SEAL | F_SEAL_SHRINK |
                                          F_SEAL_WRITE)) {
            Ok(_) => (),
            Err(nix::Error::Sys(errno)) => return Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        };

        SealedMemFd::new(fd)
    }

    // Not implementing AsRawFd trait because this is unsafe
    pub unsafe fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for MemFd {
    fn drop(&mut self) {
        let _ = self.unmap();
        if self.fd != -1 {
            let _ = close(self.fd);
        }
    }
}

impl IntoRawFd for MemFd {
    fn into_raw_fd(self) -> RawFd {
        match self.seal() {
            Ok(sealed) => sealed.into_raw_fd(),
            Err(_) => -1,
        }
    }
}

impl SealedMemFd {
    pub fn new(fd: RawFd) -> Result<SealedMemFd, io::Error> {
        let mut memfd = SealedMemFd {
            fd: fd,
            map: SealedMap::Unmapped,
        };

        try!(memfd.ensure_seals());
        try!(memfd.update_map());

        Ok(memfd)
    }

    fn ensure_seals(&self) -> Result<(), io::Error> {
        match fcntl(self.fd, FcntlArg::F_GET_SEALS) {
            Ok(seals) if SealFlag::from_bits_truncate(seals) ==
                         F_SEAL_GROW | F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_WRITE => Ok(()),
            Ok(seals) => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied,
                                   format!("memfd is not sealed: {:?}",
                                           SealFlag::from_bits_truncate(seals))))
            }
            Err(nix::Error::Sys(errno)) => Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        }
    }

    fn unmap(&mut self) -> Result<(), io::Error> {
        match self.map {
            SealedMap::ReadOnly(p, size) => {
                match munmap(p, size) {
                    Ok(_) => {
                        self.map = SealedMap::Unmapped;
                        Ok(())
                    }
                    Err(nix::Error::Sys(errno)) => {
                        self.map = SealedMap::Unmapped;
                        Err(io::Error::from_raw_os_error(errno as i32))
                    }
                    Err(_) => unreachable!(),
                }
            }
            SealedMap::Unmapped => Ok(()),
        }
    }

    fn update_map(&mut self) -> Result<(), io::Error> {
        try!(self.unmap());

        let size = try!(self.get_size());

        let p = match mmap(ptr::null_mut(),
                           size as size_t,
                           PROT_READ,
                           MAP_PRIVATE,
                           self.fd,
                           0) {
            Ok(p) => p,
            Err(nix::Error::Sys(errno)) => return Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        };

        self.map = SealedMap::ReadOnly(p, size);

        Ok(())
    }

    pub fn get_size(&self) -> Result<usize, io::Error> {
        match fstat(self.fd) {
            Ok(stat) => Ok(stat.st_size as usize),
            Err(nix::Error::Sys(errno)) => Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        }
    }

    pub fn as_slice<'a>(&'a self) -> Result<&'a [u8], io::Error> {
        let size = try!(self.get_size());
        if size == 0 {
            return Ok(&[]);
        }

        match self.map {
            SealedMap::ReadOnly(p, s) => Ok(unsafe { slice::from_raw_parts(p as *const u8, s) }),
            SealedMap::Unmapped => unreachable!(),
        }
    }

    // Not implementing Clone trait because this can fail
    pub fn clone(&self) -> Result<SealedMemFd, io::Error> {
        let new_fd = match dup(self.fd) {
            Ok(fd) => fd,
            Err(nix::Error::Sys(errno)) => return Err(io::Error::from_raw_os_error(errno as i32)),
            Err(_) => unreachable!(),
        };

        SealedMemFd::new(new_fd)
    }
}

impl Drop for SealedMemFd {
    fn drop(&mut self) {
        let _ = self.unmap();
        if self.fd != -1 {
            let _ = close(self.fd);
        }
    }
}

impl AsRawFd for SealedMemFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for SealedMemFd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.fd;
        self.fd = -1;
        // unmap happens on drop

        fd
    }
}
