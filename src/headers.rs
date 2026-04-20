use ls_qpack_rs::decoder::{Decoder, DecoderOutput};
use ls_qpack_rs::encoder::Encoder;
use ls_qpack_rs::StreamId;
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

    pub fn feed_decoder<'a>(&mut self, py: Python<'a>, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let input_data = data.as_bytes();

        let res = py.detach(|| self.encoder.feed(input_data));

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
        let mut decoded_vec: Vec<(&str, &str)> = Vec::with_capacity(headers.len());

        for (header, value) in headers.iter() {
            let header_str = std::str::from_utf8(header.as_bytes()).map_err(|e| {
                EncoderStreamError::new_err(format!("Invalid UTF-8 in header: {}", e))
            })?;
            let value_str = std::str::from_utf8(value.as_bytes()).map_err(|e| {
                EncoderStreamError::new_err(format!("Invalid UTF-8 in value: {}", e))
            })?;
            decoded_vec.push((header_str, value_str));
        }

        let res = py.detach(|| {
            self.encoder
                .encode_all(StreamId::new(stream_id), decoded_vec)
        });

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

    pub fn feed_encoder<'a>(&mut self, py: Python<'a>, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let input_data = data.as_bytes();

        let res = py.detach(|| self.decoder.feed(input_data));

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
        let input_data = data.as_bytes();

        let output = py.detach(|| self.decoder.decode(StreamId::new(stream_id), input_data));

        match output {
            Ok(DecoderOutput::Done(ref buffer)) => {
                let decoded_headers = PyList::new(
                    py,
                    Vec::<(String, String)>::with_capacity(buffer.headers().len()),
                )
                .unwrap();

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
        let output = py.detach(|| self.decoder.unblocked(StreamId::new(stream_id)));

        if output.is_none() {
            return Err(DecoderStreamError::new_err("stream id is unknown"));
        }

        let res = output.unwrap();

        match res {
            Ok(DecoderOutput::Done(ref buffer)) => {
                let headers_iter = buffer.headers();
                let decoded_headers = PyList::new(
                    py,
                    Vec::<(String, String)>::with_capacity(headers_iter.len()),
                )
                .unwrap();

                for header in headers_iter {
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
