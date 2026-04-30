use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, pyfunction, Bound, Py};
use pyo3::{pymethods, PyResult, Python};

pyo3::create_exception!(_hazmat, BufferReadError, PyValueError);
pyo3::create_exception!(_hazmat, BufferWriteError, PyValueError);

/// Wrapper around a raw pointer that is Send + Sync.
/// Safety: the pointer is only accessed when GIL is held (in pymethods),
/// and the Py<PyBytes> prevents the underlying data from being freed.
struct SendPtr(*const u8);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

enum BufferStorage {
    /// Owned mutable buffer (write mode).
    Owned(Vec<u8>),
    /// Borrowed immutable buffer referencing a PyBytes (read mode, zero-copy).
    Borrowed {
        _obj: Py<PyBytes>,
        ptr: SendPtr,
        len: usize,
    },
}

impl BufferStorage {
    #[inline(always)]
    fn as_slice(&self) -> &[u8] {
        match self {
            BufferStorage::Owned(v) => v.as_slice(),
            BufferStorage::Borrowed { ptr, len, .. } => {
                // SAFETY: _obj prevents GC, PyBytes is immutable, GIL is held
                unsafe { std::slice::from_raw_parts(ptr.0, *len) }
            }
        }
    }

    #[inline(always)]
    fn as_mut_slice(&mut self) -> Result<&mut [u8], PyResult<()>> {
        match self {
            BufferStorage::Owned(v) => Ok(v.as_mut_slice()),
            BufferStorage::Borrowed { .. } => {
                Err(Err(BufferWriteError::new_err("Buffer is read-only")))
            }
        }
    }
}

#[pyclass(module = "qh3._hazmat")]
pub struct Buffer {
    pos: usize,
    storage: BufferStorage,
    capacity: usize,
}

/// Non-pymethod helpers for internal Rust access.
impl Buffer {
    #[inline(always)]
    pub fn data_ref(&self) -> &[u8] {
        self.storage.as_slice()
    }

    #[inline(always)]
    pub fn data_mut(&mut self) -> Result<&mut [u8], pyo3::PyErr> {
        match &mut self.storage {
            BufferStorage::Owned(v) => Ok(v.as_mut_slice()),
            BufferStorage::Borrowed { .. } => Err(BufferWriteError::new_err("Buffer is read-only")),
        }
    }

    #[inline(always)]
    pub fn get_pos(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline(always)]
    pub fn get_capacity(&self) -> usize {
        self.capacity
    }
}

#[pymethods]
impl Buffer {
    #[new]
    #[pyo3(signature = (capacity=None, data=None, length=None))]
    pub fn py_new(
        capacity: Option<usize>,
        data: Option<Bound<'_, PyBytes>>,
        length: Option<usize>,
    ) -> PyResult<Self> {
        if let Some(payload) = data {
            let bytes_slice = payload.as_bytes();
            let cap = length.unwrap_or(bytes_slice.len()).min(bytes_slice.len());
            let ptr = bytes_slice.as_ptr();
            let len = bytes_slice.len();
            let obj: Py<PyBytes> = payload.unbind();

            return Ok(Buffer {
                pos: 0,
                storage: BufferStorage::Borrowed {
                    _obj: obj,
                    ptr: SendPtr(ptr),
                    len,
                },
                capacity: cap,
            });
        }

        if capacity.is_none() {
            return Err(PyValueError::new_err(
                "mandatory capacity without data args",
            ));
        }

        Ok(Buffer {
            pos: 0,
            storage: BufferStorage::Owned(vec![0; capacity.unwrap()]),
            capacity: capacity.unwrap(),
        })
    }

    #[getter]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[getter]
    pub fn data<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        if self.pos == 0 {
            return PyBytes::new(py, &[]);
        }
        let slice = self.storage.as_slice();
        PyBytes::new(py, &slice[0_usize..self.pos])
    }

    /// Returns the full underlying buffer data (for read-mode buffers).
    #[getter]
    pub fn raw_data<'a>(&self, py: Python<'a>) -> Bound<'a, PyBytes> {
        let slice = self.storage.as_slice();
        PyBytes::new(py, &slice[0_usize..self.capacity])
    }

    pub fn data_slice<'a>(
        &self,
        py: Python<'a>,
        start: usize,
        end: usize,
    ) -> PyResult<Bound<'a, PyBytes>> {
        if self.capacity < start || self.capacity < end || end < start {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        Ok(PyBytes::new(py, &slice[start..end]))
    }

    #[inline(always)]
    #[pyo3(signature = ())]
    pub fn eof(&self) -> bool {
        self.pos == self.capacity
    }

    #[inline]
    pub fn seek(&mut self, pos: usize) -> PyResult<()> {
        if pos > self.capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        self.pos = pos;

        Ok(())
    }

    #[inline(always)]
    #[pyo3(signature = ())]
    pub fn tell(&self) -> usize {
        self.pos
    }

    #[pyo3(signature = (length))]
    pub fn pull_bytes<'a>(
        &mut self,
        py: Python<'a>,
        length: usize,
    ) -> PyResult<Bound<'a, PyBytes>> {
        if self.capacity < self.pos + length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract = PyBytes::new(py, &slice[self.pos..(self.pos + length)]);

        self.pos += length;

        Ok(extract)
    }

    #[inline(always)]
    #[pyo3(signature = ())]
    pub fn pull_uint8(&mut self) -> PyResult<u8> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract = slice[self.pos];
        self.pos += 1;

        Ok(extract)
    }

    #[inline]
    #[pyo3(signature = ())]
    pub fn pull_uint16(&mut self) -> PyResult<u16> {
        let end_offset = self.pos + 2;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract = u16::from_be_bytes(slice[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline]
    #[pyo3(signature = ())]
    pub fn pull_uint24(&mut self) -> PyResult<u32> {
        let end_offset = self.pos + 3;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract =
            u32::from_be_bytes([0, slice[self.pos], slice[self.pos + 1], slice[self.pos + 2]]);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline]
    #[pyo3(signature = ())]
    pub fn pull_uint32(&mut self) -> PyResult<u32> {
        let end_offset = self.pos + 4;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract = u32::from_be_bytes(slice[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline]
    #[pyo3(signature = ())]
    pub fn pull_uint64(&mut self) -> PyResult<u64> {
        let end_offset = self.pos + 8;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let extract = u64::from_be_bytes(slice[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[pyo3(signature = ())]
    pub fn pull_uint_var(&mut self) -> PyResult<u64> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let slice = self.storage.as_slice();
        let first = slice[self.pos];
        let var_type = first >> 6;

        match var_type {
            0 => {
                self.pos += 1;
                Ok(first.into())
            }
            1 => self.pull_uint16().map(|val| (val & 0x3FFF).into()),
            2 => self.pull_uint32().map(|val| (val & 0x3FFFFFFF).into()),
            _ => self.pull_uint64().map(|val| val & 0x3FFFFFFFFFFFFFFF),
        }
    }

    #[inline]
    pub fn push_bytes(&mut self, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let data_to_be_pushed = data.as_bytes();
        let end_pos = self.pos + data_to_be_pushed.len();

        if self.capacity < end_pos {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        let buf = self.storage.as_mut_slice().map_err(|e| e.unwrap_err())?;
        buf[self.pos..end_pos].copy_from_slice(data_to_be_pushed);
        self.pos = end_pos;

        Ok(())
    }

    #[inline]
    pub fn push_uint8(&mut self, value: u8) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        let buf = self.storage.as_mut_slice().map_err(|e| e.unwrap_err())?;
        buf[self.pos] = value;
        self.pos += 1;

        Ok(())
    }

    #[inline]
    pub fn push_uint16(&mut self, value: u16) -> PyResult<()> {
        let end_offset = self.pos + 2;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        let buf = self.storage.as_mut_slice().map_err(|e| e.unwrap_err())?;
        buf[self.pos..end_offset].copy_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    #[inline]
    pub fn push_uint32(&mut self, value: u32) -> PyResult<()> {
        let end_offset = self.pos + 4;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        let buf = self.storage.as_mut_slice().map_err(|e| e.unwrap_err())?;
        buf[self.pos..end_offset].copy_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    #[inline]
    pub fn push_uint64(&mut self, value: u64) -> PyResult<()> {
        let end_offset = self.pos + 8;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        let buf = self.storage.as_mut_slice().map_err(|e| e.unwrap_err())?;
        buf[self.pos..end_offset].copy_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    pub fn push_uint_var(&mut self, value: u64) -> PyResult<()> {
        if value <= 0x3F {
            return self.push_uint8(value.try_into().unwrap());
        } else if value <= 0x3FFF {
            return self.push_uint16((value | 0x4000).try_into().unwrap());
        } else if value <= 0x3FFFFFFF {
            return self.push_uint32((value | 0x80000000).try_into().unwrap());
        } else if value <= 0x3FFFFFFFFFFFFFFF {
            return self.push_uint64(value | 0xC000000000000000);
        }

        Err(PyValueError::new_err(
            "Integer is too big for a variable-length integer",
        ))
    }
}

#[pyfunction]
pub fn encode_uint_var(value: u64) -> PyResult<Vec<u8>> {
    if value <= 0x3F {
        Ok(vec![value as u8])
    } else if value <= 0x3FFF {
        let encoded: u16 = 0x4000 | (value as u16);
        Ok(encoded.to_be_bytes().to_vec())
    } else if value <= 0x3FFFFFFF {
        let encoded: u32 = 0x8000_0000 | (value as u32);
        Ok(encoded.to_be_bytes().to_vec())
    } else if value <= 0x3FFFFFFFFFFFFFFF {
        let encoded: u64 = 0xC000_0000_0000_0000 | value;
        Ok(encoded.to_be_bytes().to_vec())
    } else {
        Err(PyValueError::new_err(
            "Value too large to encode as a variable-length integer",
        ))
    }
}

#[pyfunction]
pub fn size_uint_var(value: u64) -> PyResult<u8> {
    // 1-byte
    if value <= 0x3F {
        Ok(1)
    }
    // 2-bytes
    else if value <= 0x3FFF {
        Ok(2)
    }
    // 4-bytes
    else if value <= 0x3FFFFFFF {
        Ok(4)
    }
    // 8-bytes
    else if value <= 0x3FFFFFFFFFFFFFFF {
        Ok(8)
    } else {
        Err(PyValueError::new_err(
            "Integer is too big for a variable-length integer",
        ))
    }
}
