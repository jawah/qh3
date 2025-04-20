use pyo3::exceptions::PyValueError;
use pyo3::types::PyBytes;
use pyo3::types::PyBytesMethods;
use pyo3::{pyclass, pyfunction, Bound};
use pyo3::{pymethods, PyResult, Python};

pyo3::create_exception!(_hazmat, BufferReadError, PyValueError);
pyo3::create_exception!(_hazmat, BufferWriteError, PyValueError);

#[pyclass(module = "qh3._hazmat")]
pub struct Buffer {
    pos: usize,
    data: Vec<u8>,
    capacity: usize,
}

#[pymethods]
impl Buffer {
    #[new]
    #[pyo3(signature = (capacity=None, data=None))]
    pub fn py_new(capacity: Option<usize>, data: Option<Bound<'_, PyBytes>>) -> PyResult<Self> {
        if data.is_some() {
            let payload = data.unwrap();
            let initial_content = payload.as_bytes().to_vec();
            let length = initial_content.len();

            return Ok(Buffer {
                pos: 0,
                data: initial_content,
                capacity: length,
            });
        }

        if capacity.is_none() {
            return Err(PyValueError::new_err(
                "mandatory capacity without data args",
            ));
        }

        Ok(Buffer {
            pos: 0,
            data: vec![0; capacity.unwrap()],
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
        PyBytes::new(py, &self.data[0_usize..self.pos])
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

        Ok(PyBytes::new(py, &self.data[start..end]))
    }

    #[inline(always)]
    pub fn eof(&self) -> bool {
        self.pos == self.capacity
    }

    #[inline(always)]
    pub fn seek(&mut self, pos: usize) -> PyResult<()> {
        if pos > self.capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        self.pos = pos;

        Ok(())
    }

    #[inline(always)]
    pub fn tell(&self) -> usize {
        self.pos
    }

    #[inline(always)]
    pub fn pull_bytes<'a>(
        &mut self,
        py: Python<'a>,
        length: usize,
    ) -> PyResult<Bound<'a, PyBytes>> {
        if self.capacity < self.pos + length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = PyBytes::new(py, &self.data[self.pos..(self.pos + length)]);

        self.pos += length;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint8(&mut self) -> PyResult<u8> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = self.data[self.pos];
        self.pos += 1;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint16(&mut self) -> PyResult<u16> {
        let end_offset = self.pos + 2;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u16::from_be_bytes(self.data[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint24(&mut self) -> PyResult<u32> {
        let end_offset = self.pos + 3;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let tmp = vec![
            0,
            self.data[self.pos],
            self.data[self.pos] + 1,
            self.data[self.pos] + 2,
        ];

        let extract = u32::from_be_bytes(tmp.try_into().unwrap());
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint32(&mut self) -> PyResult<u32> {
        let end_offset = self.pos + 4;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u32::from_be_bytes(self.data[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint64(&mut self) -> PyResult<u64> {
        let end_offset = self.pos + 8;

        if self.capacity < end_offset {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u64::from_be_bytes(self.data[self.pos..end_offset].try_into()?);
        self.pos = end_offset;

        Ok(extract)
    }

    #[inline(always)]
    pub fn pull_uint_var(&mut self) -> PyResult<u64> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let first = self.data[self.pos];
        let var_type = first >> 6;

        if var_type == 0 {
            self.pos += 1;
            return Ok(first.into());
        }

        if var_type == 1 {
            return match self.pull_uint16() {
                Ok(val) => {
                    return Ok((val & 0x3FFF).into());
                }
                Err(exception) => Err(exception),
            };
        }

        if var_type == 2 {
            return match self.pull_uint32() {
                Ok(val) => {
                    return Ok((val & 0x3FFFFFFF).into());
                }
                Err(exception) => Err(exception),
            };
        }

        match self.pull_uint64() {
            Ok(val) => Ok(val & 0x3FFFFFFFFFFFFFFF),
            Err(exception) => Err(exception),
        }
    }

    #[inline(always)]
    pub fn push_bytes(&mut self, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let data_to_be_pushed = data.as_bytes();
        let end_pos = self.pos + data_to_be_pushed.len();

        if self.capacity < end_pos {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos..end_pos].clone_from_slice(data_to_be_pushed);
        self.pos = end_pos;

        Ok(())
    }

    #[inline(always)]
    pub fn push_uint8(&mut self, value: u8) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos] = value;
        self.pos += 1;

        Ok(())
    }

    #[inline(always)]
    pub fn push_uint16(&mut self, value: u16) -> PyResult<()> {
        let end_offset = self.pos + 2;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos..end_offset].clone_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    #[inline(always)]
    pub fn push_uint32(&mut self, value: u32) -> PyResult<()> {
        let end_offset = self.pos + 4;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos..end_offset].clone_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    #[inline(always)]
    pub fn push_uint64(&mut self, value: u64) -> PyResult<()> {
        let end_offset = self.pos + 8;

        if self.capacity < end_offset {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos..end_offset].clone_from_slice(&value.to_be_bytes());
        self.pos = end_offset;

        Ok(())
    }

    #[inline(always)]
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
    // 1-byte
    if value <= 0x3F {
        // For one byte, the two MSB are 00 (implicitly true if value < 64)
        Ok([value as u8].into())
    }
    // 2-bytes
    else if value <= 0x3FFF {
        // Set the two MSB to 01. For a 16-bit value, that is equivalent to OR-ing with 0x4000.
        let encoded: u16 = 0x4000 | (value as u16);
        Ok(encoded.to_be_bytes().into())
    }
    // 4-bytes
    else if value <= 0x3FFFFFFF {
        // Two MSB = 10 for a 32-bit value is equivalent to OR-ing with 0x8000_0000.
        let encoded: u32 = 0x8000_0000 | (value as u32);
        Ok(encoded.to_be_bytes().into())
    }
    // 8-bytes
    else if value <= 0x3FFFFFFFFFFFFFFF {
        // Two MSB = 11 for a 64-bit value is equivalent to OR-ing with 0xC000_0000_0000_0000.
        let encoded: u64 = 0xC000_0000_0000_0000 | value;
        Ok(encoded.to_be_bytes().into())
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
