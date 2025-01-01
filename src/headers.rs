use ls_qpack::decoder::{Decoder, DecoderOutput};
use ls_qpack::encoder::Encoder;
use ls_qpack::StreamId;
use pyo3::exceptions::PyException;
use pyo3::pymethods;
use pyo3::types::PyBytesMethods;
use pyo3::types::PyListMethods;
use pyo3::types::{PyBytes, PyList, PyTuple};
use pyo3::{pyclass, Bound};
use pyo3::{IntoPyObject, PyResult, Python};

pyo3::create_exception!(_hazmat, StreamBlocked, PyException);
pyo3::create_exception!(_hazmat, EncoderStreamError, PyException);
pyo3::create_exception!(_hazmat, DecoderStreamError, PyException);
pyo3::create_exception!(_hazmat, DecompressionFailed, PyException);

#[pyclass(name = "QpackDecoder", module = "qh3._hazmat")]
pub struct QpackDecoder {
    decoder: Decoder,
}

#[pyclass(name = "QpackEncoder", module = "qh3._hazmat")]
pub struct QpackEncoder {
    encoder: Encoder,
}

unsafe impl Send for QpackDecoder {}
unsafe impl Send for QpackEncoder {}
unsafe impl Sync for QpackDecoder {}
unsafe impl Sync for QpackEncoder {}

#[pymethods]
impl QpackEncoder {
    #[new]
    pub fn py_new() -> Self {
        QpackEncoder {
            encoder: Encoder::new(),
        }
    }

    pub fn apply_settings<'a>(
        &mut self,
        py: Python<'a>,
        max_table_capacity: u32,
        dyn_table_capacity: u32,
        blocked_streams: u32,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let r =
            match self
                .encoder
                .configure(max_table_capacity, dyn_table_capacity, blocked_streams)
            {
                Ok(r) => r,
                Err(_) => return Err(EncoderStreamError::new_err("failed to configure encoder")),
            };

        Ok(PyBytes::new(py, r.data()))
    }

    pub fn feed_decoder(&mut self, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let res = self.encoder.feed(data.as_bytes());

        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(DecoderStreamError::new_err(
                "an error occurred while feeding data from decoder with qpack data",
            )),
        }
    }

    pub fn encode<'a>(
        &mut self,
        py: Python<'a>,
        stream_id: u64,
        headers: Vec<(Bound<'_, PyBytes>, Bound<'_, PyBytes>)>,
    ) -> PyResult<Bound<'a, PyTuple>> {
        let mut decoded_vec: Vec<(String, String)> = Vec::new();

        for (header, value) in headers.iter() {
            decoded_vec.push((
                std::str::from_utf8(header.as_bytes()).unwrap().to_string(),
                std::str::from_utf8(value.as_bytes()).unwrap().to_string(),
            ));
        }

        let res = self
            .encoder
            .encode_all(StreamId::new(stream_id), decoded_vec);

        match res {
            Ok(buffer) => {
                let encoded_buffer = PyBytes::new(py, buffer.header());

                let stream_data = PyBytes::new(py, buffer.stream());

                Ok(PyTuple::new(py, [stream_data, encoded_buffer]).unwrap())
            }
            Err(abc) => Err(EncoderStreamError::new_err(format!(
                "unable to encode headers {:?}",
                abc
            ))),
        }
    }
}

#[pymethods]
impl QpackDecoder {
    #[new]
    pub fn py_new(max_table_capacity: u32, blocked_streams: u32) -> Self {
        QpackDecoder {
            decoder: Decoder::new(max_table_capacity, blocked_streams),
        }
    }

    pub fn feed_encoder(&mut self, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let res = self.decoder.feed(data.as_bytes());

        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(EncoderStreamError::new_err(
                "an error occurred while feeding data from encoder with qpack data",
            )),
        }
    }

    pub fn feed_header<'a>(
        &mut self,
        py: Python<'a>,
        stream_id: u64,
        data: Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'a, PyTuple>> {
        let output = self
            .decoder
            .decode(StreamId::new(stream_id), data.as_bytes());

        match output {
            Ok(DecoderOutput::Done(ref buffer)) => {
                let decoded_headers = PyList::new(py, Vec::<(String, String)>::new()).unwrap();

                for header in buffer.headers() {
                    let _ = decoded_headers.append(
                        PyTuple::new(
                            py,
                            [
                                PyBytes::new(py, header.name().as_bytes()),
                                PyBytes::new(py, header.value().as_bytes()),
                            ],
                        )
                        .unwrap(),
                    );
                }

                Ok(PyTuple::new(
                    py,
                    [
                        PyBytes::new(py, buffer.stream())
                            .into_pyobject(py)?
                            .into_any(),
                        decoded_headers.into_pyobject(py)?.into_any(),
                    ],
                )
                .unwrap())
            }
            Ok(DecoderOutput::BlockedStream) => Err(StreamBlocked::new_err(
                "stream is blocked, need more data to pursue decoding",
            )),
            Err(_) => Err(DecoderStreamError::new_err(
                "an error occurred while decoding the stream qpack data",
            )),
        }
    }

    pub fn resume_header<'a>(
        &mut self,
        py: Python<'a>,
        stream_id: u64,
    ) -> PyResult<Bound<'a, PyTuple>> {
        let output = self.decoder.unblocked(StreamId::new(stream_id));

        if output.is_none() {
            return Err(DecoderStreamError::new_err("stream id is unknown"));
        }

        let res = output.unwrap();

        match res {
            Ok(DecoderOutput::Done(ref buffer)) => {
                let decoded_headers = PyList::new(py, Vec::<(String, String)>::new()).unwrap();

                for header in buffer.headers() {
                    let _ = decoded_headers.append(
                        PyTuple::new(
                            py,
                            [
                                PyBytes::new(py, header.name().as_bytes()),
                                PyBytes::new(py, header.value().as_bytes()),
                            ],
                        )
                        .unwrap(),
                    );
                }

                Ok(PyTuple::new(
                    py,
                    [
                        PyBytes::new(py, buffer.stream())
                            .into_pyobject(py)?
                            .into_any(),
                        decoded_headers.into_pyobject(py)?.into_any(),
                    ],
                )
                .unwrap())
            }
            Ok(DecoderOutput::BlockedStream) => Err(StreamBlocked::new_err(
                "stream is blocked, need more data to pursue decoding",
            )),
            Err(_) => Err(DecoderStreamError::new_err(
                "an error occurred while decoding the stream qpack data",
            )),
        }
    }
}
