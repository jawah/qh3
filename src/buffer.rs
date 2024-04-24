use pyo3::types::{PyBytes};
use pyo3::{pymethods, PyResult, Python};
use pyo3::pyclass;
use pyo3::exceptions::{PyValueError};

pyo3::create_exception!(_hazmat, BufferReadError, PyValueError);
pyo3::create_exception!(_hazmat, BufferWriteError, PyValueError);


#[pyclass(module = "qh3._hazmat")]
pub struct Buffer {
    pos: u64,
    data: Vec<u8>,
    capacity: u64
}


#[pymethods]
impl Buffer {
    #[new]
    pub fn py_new(capacity: Option<u64>, data: Option<&PyBytes>) -> PyResult<Self> {
        if data.is_some() {
            let payload = data.unwrap().as_bytes();
            return Ok(
                Buffer {
                    pos: 0,
                    data: payload.to_vec(),
                    capacity: payload.len() as u64
                }
            );
        }

        if !capacity.is_some() {
            return Err(
                PyValueError::new_err("mandatory capacity without data args")
            );
        }

        return Ok(
            Buffer {
                pos: 0,
                data: vec![0; capacity.unwrap().try_into().unwrap()],
                capacity: capacity.unwrap(),
            }
        );
    }

    #[getter]
    pub fn capacity(&self) -> u64 {
        return self.capacity;
    }

    #[getter]
    pub fn data<'a>(&self, py: Python<'a>) -> &'a PyBytes {
        if self.pos == 0 {
            return PyBytes::new(
                py,
                &[]
            );
        }
        return PyBytes::new(
            py,
            &self.data[0 as usize..self.pos as usize]
        );
    }

    pub fn data_slice<'a>(&self, py: Python<'a>, start: u64, end: u64) -> PyResult<&'a PyBytes> {
        if self.capacity < start || self.capacity < end || end < start {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        return Ok(
            PyBytes::new(
                py,
                &self.data[start as usize..end as usize]
            )
        );
    }

    pub fn eof(&self) -> bool {
        return self.pos == self.capacity;
    }

    pub fn seek(&mut self, pos: u64) -> PyResult<()> {
        if pos > self.capacity {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        self.pos = pos;

        return Ok(());
    }

    pub fn tell(&self) -> u64 {
        return self.pos;
    }

    pub fn pull_bytes<'a>(&mut self, py: Python<'a>, length: u64) -> PyResult<&'a PyBytes> {
        if self.capacity < self.pos + length {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = PyBytes::new(
            py,
            &self.data[self.pos as usize..(self.pos+length) as usize]
        );

        self.pos += length;

        return Ok(extract);
    }

    pub fn pull_uint8(&mut self) -> PyResult<u8> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = self.data[self.pos as usize];
        self.pos += 1;

        return Ok(extract);
    }

    pub fn pull_uint16(&mut self) -> PyResult<u16> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        if self.capacity < self.pos + 2 {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u16::from_be_bytes(self.data[self.pos as usize..(self.pos + 2) as usize].try_into().expect("failure"));
        self.pos += 2;

        return Ok(extract);
    }

    pub fn pull_uint32(&mut self) -> PyResult<u32> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        if self.capacity < self.pos + 4 {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u32::from_be_bytes(self.data[self.pos as usize..(self.pos + 4) as usize].try_into().expect("failure"));
        self.pos += 4;

        return Ok(extract);
    }

    pub fn pull_uint64(&mut self) -> PyResult<u64> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        if self.capacity < self.pos + 8 {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let extract = u64::from_be_bytes(self.data[self.pos as usize..(self.pos + 8) as usize].try_into().expect("failure"));
        self.pos += 8;

        return Ok(extract);
    }

    pub fn pull_uint_var(&mut self) -> PyResult<u64> {
        if self.eof() {
            return Err(BufferReadError::new_err("Read out of bounds"));
        }

        let first = self.data[self.pos as usize];
        let var_type = first >> 6;

        if var_type == 0 {
            self.pos += 1;
            return Ok(first.into());
        }

        if var_type == 1 {
            return match self.pull_uint16() {
                Ok(val) => {
                    return Ok((val & 0x3FFF).into());
                },
                Err(exception) => Err(exception)
            };
        }

        if var_type == 2 {
            return match self.pull_uint32() {
                Ok(val) => {
                    return Ok((val & 0x3FFFFFFF).into());
                },
                Err(exception) => Err(exception)
            };
        }

        return match self.pull_uint64() {
            Ok(val) => {
                return Ok(val & 0x3FFFFFFFFFFFFFFF);
            },
            Err(exception) => Err(exception)
        };
    }

    pub fn push_bytes(&mut self, data: &PyBytes) -> PyResult<()> {
        let data_to_be_pushed = data.as_bytes();
        let end_pos = self.pos + data_to_be_pushed.len() as u64;

        if self.capacity < end_pos {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos as usize..end_pos as usize].clone_from_slice(&data_to_be_pushed);
        self.pos = end_pos;

        return Ok(());
    }

    pub fn push_uint8(&mut self, value: u8) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos as usize] = value;
        self.pos += 1;

        return Ok(());
    }

    pub fn push_uint16(&mut self, value: u16) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        if self.capacity < self.pos + 2 {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos as usize..(self.pos + 2) as usize].clone_from_slice(&value.to_be_bytes());
        self.pos += 2;

        return Ok(());
    }

    pub fn push_uint32(&mut self, value: u32) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        if self.capacity < self.pos + 4 {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos as usize..(self.pos + 4) as usize].clone_from_slice(&value.to_be_bytes());
        self.pos += 4;

        return Ok(());
    }

    pub fn push_uint64(&mut self, value: u64) -> PyResult<()> {
        if self.eof() {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        if self.capacity < self.pos + 8 {
            return Err(BufferWriteError::new_err("Write out of bounds"));
        }

        self.data[self.pos as usize..(self.pos + 8) as usize].clone_from_slice(&value.to_be_bytes());
        self.pos += 8;

        return Ok(());
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

        return Err(PyValueError::new_err("Integer is too big for a variable-length integer"));
    }
}
