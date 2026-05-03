//! Python-exposed UDP socket helpers using quinn-udp.
//!
//! The Python side owns the socket and manages the event loop.
//! This module only provides the fast syscall wrappers:
//! - `recv()`: recvmmsg/recvmsg_x (batched) with automatic GRO splitting
//! - `send()`: sendmsg/sendmsg_x with automatic GSO coalescing
//!
//! On Linux:  recvmmsg + sendmsg with UDP_SEGMENT (kernel GRO/GSO)
//! On macOS:  recvmsg_x + sendmsg_x (Apple private batch APIs)

#[cfg(unix)]
use std::io::IoSliceMut;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::io::{BorrowedFd, RawFd};
#[cfg(unix)]
use std::sync::Mutex;

use pyo3::prelude::*;
#[cfg(unix)]
use pyo3::types::{PyBytes, PyList, PyTuple};

#[cfg(unix)]
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, BATCH_SIZE};

/// Per-slot receive buffer size: 65536 bytes handles max GRO coalescing.
#[cfg(unix)]
const RECV_BUF_LEN: usize = 65536;

#[pyclass(name = "UdpSocketState")]
pub struct PyUdpSocketState {
    #[cfg(unix)]
    inner: quinn_udp::UdpSocketState,
    #[cfg(unix)]
    fd: RawFd,
    #[cfg(unix)]
    recv_buf: Mutex<Vec<u8>>,
    #[cfg(unix)]
    max_gso: usize,
    #[cfg(unix)]
    gro: usize,
}

#[pymethods]
impl PyUdpSocketState {
    /// Create a UdpSocketState from a file descriptor.
    ///
    /// The caller (Python transport) is responsible for socket creation,
    /// binding, and enabling GRO/GSO via setsockopt. This constructor
    /// only initialises the quinn-udp state needed for recv/send syscalls.
    #[new]
    fn new(fd: i64) -> PyResult<Self> {
        #[cfg(unix)]
        {
            let raw_fd = fd as RawFd;
            let borrowed = unsafe { BorrowedFd::borrow_raw(raw_fd) };
            let sock_ref = UdpSockRef::from(&borrowed);

            let state = quinn_udp::UdpSocketState::new(sock_ref)
                .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;

            // Enable Apple's private sendmsg_x/recvmsg_x batch APIs when available.
            // These are resolved via dlsym at runtime; if the symbols are absent
            // the fast path is automatically disabled on first use.
            // The `fast-apple-datapath` feature of quinn-udp is always enabled in
            // Cargo.toml, so `set_apple_fast_path()` is compiled on Apple targets.
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "tvos",
                target_os = "visionos",
                target_os = "watchos"
            ))]
            // SAFETY: quinn-udp resolves sendmsg_x / recvmsg_x via dlsym at
            // runtime and falls back gracefully if the symbols are not present.
            unsafe {
                state.set_apple_fast_path();
            }

            let max_gso = state.max_gso_segments();
            let gro = state.gro_segments();

            Ok(Self {
                inner: state,
                fd: raw_fd,
                recv_buf: Mutex::new(vec![0u8; RECV_BUF_LEN * BATCH_SIZE]),
                max_gso,
                gro,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "UdpSocketState is only supported on Unix platforms",
            ))
        }
    }

    #[getter]
    fn max_gso_segments(&self) -> usize {
        #[cfg(unix)]
        {
            self.max_gso
        }
        #[cfg(not(unix))]
        {
            1
        }
    }

    #[getter]
    fn gro_segments(&self) -> usize {
        #[cfg(unix)]
        {
            self.gro
        }
        #[cfg(not(unix))]
        {
            1
        }
    }

    #[getter]
    fn may_fragment(&self) -> bool {
        #[cfg(unix)]
        {
            self.inner.may_fragment()
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// Batch-receive datagrams via recvmmsg with GRO splitting.
    ///
    /// Returns ``(list[bytes], addr)`` where *addr* is
    /// ``(ip_str, port, flowinfo, scope_id)`` from the first message.
    /// All datagrams in the list originate from that address (client
    /// sockets only talk to one peer).
    ///
    /// Returns ``([], None)`` when the socket would block.
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        #[cfg(unix)]
        {
            let mut buf = self.recv_buf.lock().unwrap();
            let slot_count = buf.len() / RECV_BUF_LEN;
            let mut metas = vec![RecvMeta::default(); slot_count];

            let mut iovs: Vec<IoSliceMut<'_>> =
                buf.chunks_mut(RECV_BUF_LEN).map(IoSliceMut::new).collect();

            let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
            let sock_ref = UdpSockRef::from(&borrowed);

            let n = match self.inner.recv(sock_ref, &mut iovs, &mut metas) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let empty = PyList::empty(py);
                    return PyTuple::new(py, [empty.as_any(), py.None().bind(py)]);
                }
                Err(e) => {
                    return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                }
            };

            if n == 0 {
                let empty = PyList::empty(py);
                return PyTuple::new(py, [empty.as_any(), py.None().bind(py)]);
            }

            // Build address tuple from first message's source.
            let first_addr = &metas[0].addr;
            let addr_obj = match first_addr {
                SocketAddr::V4(a) => {
                    let ip = a.ip().to_string();
                    PyTuple::new(
                        py,
                        &[
                            ip.into_pyobject(py)?.into_any(),
                            a.port().into_pyobject(py)?.into_any(),
                        ],
                    )?
                }
                SocketAddr::V6(a) => {
                    let ip = a.ip().to_string();
                    PyTuple::new(
                        py,
                        &[
                            ip.into_pyobject(py)?.into_any(),
                            a.port().into_pyobject(py)?.into_any(),
                            a.flowinfo().into_pyobject(py)?.into_any(),
                            a.scope_id().into_pyobject(py)?.into_any(),
                        ],
                    )?
                }
            };

            let mut segments: Vec<Bound<'py, PyBytes>> = Vec::new();
            for i in 0..n {
                let meta = &metas[i];
                let data = &iovs[i][..meta.len];
                if meta.stride > 0 && meta.len > meta.stride {
                    for chunk in data.chunks(meta.stride) {
                        segments.push(PyBytes::new(py, chunk));
                    }
                } else {
                    segments.push(PyBytes::new(py, data));
                }
            }

            let seg_list = PyList::new(py, &segments)?;
            PyTuple::new(py, [seg_list.as_any(), addr_obj.as_any()])
        }
        #[cfg(not(unix))]
        {
            let _ = py;
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "recv is only supported on Unix platforms",
            ))
        }
    }

    /// Send datagrams with automatic GSO coalescing.
    ///
    /// Accepts a Python list of `bytes` objects and accesses their
    /// underlying buffers directly via `PyBytes::as_bytes()`.
    ///
    /// Returns the number of datagrams successfully sent.
    fn send<'py>(
        &self,
        _py: Python<'py>,
        datagrams: Bound<'py, PyList>,
        addr_ip: &str,
        addr_port: u16,
    ) -> PyResult<usize> {
        let count = datagrams.len();
        if count == 0 {
            return Ok(0);
        }

        #[cfg(unix)]
        {
            let ip: IpAddr = addr_ip.parse().map_err(|e: std::net::AddrParseError| {
                pyo3::exceptions::PyValueError::new_err(e.to_string())
            })?;
            let dest = SocketAddr::new(ip, addr_port);

            let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
            let mut sent = 0usize;

            // We keep the Bound<PyBytes> handles alive so the &[u8] borrows remain valid.
            let items: Vec<Bound<'py, PyBytes>> = (0..count)
                .map(|i| {
                    datagrams
                        .get_item(i)
                        .expect("list index")
                        .cast_into::<PyBytes>()
                        .expect("expected bytes")
                })
                .collect();
            let slices: Vec<&[u8]> = items.iter().map(|b| b.as_bytes()).collect();

            if self.max_gso > 1 {
                let mut i = 0;
                while i < slices.len() {
                    let seg_size = slices[i].len();
                    let cap = self.max_gso.min(65000 / seg_size.max(1));
                    let mut end = i + 1;

                    while end < slices.len() && end - i < cap {
                        let dlen = slices[end].len();
                        if dlen == seg_size {
                            end += 1;
                        } else if dlen < seg_size {
                            end += 1;
                            break;
                        } else {
                            break;
                        }
                    }

                    let group_count = end - i;

                    // GSO requires a single contiguous buffer
                    // one copy here is unavoidable.
                    let total_len: usize = slices[i..end].iter().map(|s| s.len()).sum();
                    let mut contents = Vec::with_capacity(total_len);
                    for s in &slices[i..end] {
                        contents.extend_from_slice(s);
                    }

                    let transmit = Transmit {
                        destination: dest,
                        ecn: None,
                        contents: &contents,
                        segment_size: if group_count > 1 {
                            Some(seg_size)
                        } else {
                            None
                        },
                        src_ip: None,
                    };

                    let sock_ref = UdpSockRef::from(&borrowed);
                    match self.inner.send(sock_ref, &transmit) {
                        Ok(()) => sent += group_count,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                        }
                    }

                    i = end;
                }
            } else {
                // Non-GSO
                for s in &slices {
                    let transmit = Transmit {
                        destination: dest,
                        ecn: None,
                        contents: s,
                        segment_size: None,
                        src_ip: None,
                    };

                    let sock_ref = UdpSockRef::from(&borrowed);
                    match self.inner.send(sock_ref, &transmit) {
                        Ok(()) => sent += 1,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            return Err(pyo3::exceptions::PyOSError::new_err(e.to_string()));
                        }
                    }
                }
            }

            Ok(sent)
        }
        #[cfg(not(unix))]
        {
            let _ = (py, datagrams, addr_ip, addr_port);
            Err(pyo3::exceptions::PyNotImplementedError::new_err(
                "send is only supported on Unix platforms",
            ))
        }
    }
}
