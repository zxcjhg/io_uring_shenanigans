use anyhow::{anyhow, Result};
use std::env;
use std::fs::OpenOptions;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::ptr;

use uring_sys::{
    io_uring, io_uring_get_sqe, io_uring_prep_readv, io_uring_queue_exit, io_uring_queue_init,
    io_uring_sqe_set_data, io_uring_submit, io_uring_wait_cqe,
};

const QUEUE_DEPTH: u32 = 100;
const BLOCK_SIZE: u64 = 200;

fn main() -> Result<()> {
    let file_names: Vec<String> = env::args().skip(1).collect();
    let mut ring: io_uring = unsafe { mem::zeroed() };

    unsafe {
        io_uring_queue_init(QUEUE_DEPTH, &mut ring, 0);
    };

    for file_name in file_names {
        submit_read_request(file_name.into(), &mut ring)?;
        get_completion_and_print(&mut ring)?;
    }

    unsafe {
        io_uring_queue_exit(&mut ring);
    };
    Ok(())
}

#[repr(C)]
pub struct FileInfo {
    pub file_size: u64,
    pub iovecs: *mut libc::iovec,
}

impl FileInfo {
    pub fn new() -> Self {
        FileInfo {
            file_size: 0,
            iovecs: ptr::null_mut(),
        }
    }
}

impl Default for FileInfo {
    fn default() -> Self {
        Self::new()
    }
}

pub fn submit_read_request(file_path: PathBuf, ring: &mut io_uring) -> Result<()> {
    let file = OpenOptions::new().read(true).open(file_path)?;
    let file_size = file.metadata()?.len();
    let mut remaining_bytes = file_size;
    let num_blocks = (file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    let mut file_info = Box::new(FileInfo::new());
    file_info.file_size = file_size;
    let mut iovecs = Vec::with_capacity(num_blocks as usize);

    while remaining_bytes > 0 {
        let mut bytes_to_read = remaining_bytes;
        if remaining_bytes > BLOCK_SIZE {
            bytes_to_read = BLOCK_SIZE;
        }
        let mut iovec: libc::iovec = unsafe { mem::zeroed() };
        iovec.iov_len = bytes_to_read as libc::size_t;
        let mut buf = vec![0; bytes_to_read as usize];
        buf.shrink_to_fit();
        iovec.iov_base = buf.as_mut_ptr() as *mut libc::c_void;
        mem::forget(buf);
        iovecs.push(iovec);
        remaining_bytes -= bytes_to_read;
    }
    iovecs.shrink_to_fit();
    file_info.iovecs = iovecs.as_mut_ptr();
    mem::forget(iovecs);
    unsafe {
        let sqe = io_uring_get_sqe(ring);
        io_uring_prep_readv(
            sqe,
            file.as_raw_fd(),
            file_info.iovecs,
            num_blocks as u32,
            0,
        );
        io_uring_sqe_set_data(sqe, Box::into_raw(file_info) as *mut libc::c_void);
        if io_uring_submit(ring) == 0 {
            return Err(anyhow!("Failed to submit a new task"));
        }
    };

    Ok(())
}

pub fn get_completion_and_print(ring: &mut io_uring) -> Result<()> {
    let cqe: uring_sys::io_uring_cqe = unsafe { mem::zeroed() };
    let mut cqe = Box::into_raw(Box::new(cqe));
    let ret = unsafe { io_uring_wait_cqe(ring, &mut cqe) as i32 };
    if ret < 0 {
        return Err(anyhow!("Failed to retrieve from completion queue"));
    }
    unsafe {
        if (*cqe).res < 0 {
            return Err(anyhow!("Error in a completion queue entry"));
        }
    };

    let file_info: *mut FileInfo =
        unsafe { uring_sys::io_uring_cqe_get_data(cqe) as *mut FileInfo };
    let file_info = unsafe { Box::from_raw(file_info) };
    let num_blocks = ((file_info.file_size + BLOCK_SIZE - 1) / BLOCK_SIZE) as usize;

    let blocks = unsafe { Vec::from_raw_parts(file_info.iovecs, num_blocks, num_blocks) };

    for block in blocks {
        let text_utf = unsafe {
            std::slice::from_raw_parts(block.iov_base as *mut [u8; 4], block.iov_len).to_vec()
        };
        for char_utf8 in text_utf {
            print!("{}", String::from_utf8_lossy(&char_utf8));
        }
    }
    unsafe { uring_sys::io_uring_cqe_seen(ring, cqe) };

    Ok(())
}
