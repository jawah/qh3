use ls_qpack_rs::decoder::{BuffersDecoded, Decoder, DecoderErrorKind, DecoderOutput};
use ls_qpack_rs::encoder::Encoder;
use ls_qpack_rs::StreamId;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::pymethods;
use pyo3::types::PyBytesMethods;
use pyo3::types::{PyBytes, PyList, PyTuple};
use pyo3::{pyclass, Bound};
use pyo3::{PyResult, Python};

pyo3::create_exception!(_hazmat, StreamBlocked, PyException);
pyo3::create_exception!(_hazmat, EncoderStreamError, PyException);
pyo3::create_exception!(_hazmat, DecoderStreamError, PyException);
pyo3::create_exception!(_hazmat, DecompressionFailed, PyException);
pyo3::create_exception!(_hazmat, HeaderTooLarge, PyException);

#[pyclass(name = "QpackDecoder", module = "qh3._hazmat")]
pub struct QpackDecoder {
    decoder: Decoder,
}

#[pyclass(name = "QpackEncoder", module = "qh3._hazmat")]
pub struct QpackEncoder {
    encoder: Encoder,
}

fn decoded_to_python(py: Python<'_>, buffer: BuffersDecoded) -> PyResult<Bound<'_, PyTuple>> {
    // PyList::new preallocates from this exact-size iterator. No temporary
    // vector or repeated Python-list growth is needed.
    let headers = PyList::new(
        py,
        buffer.headers().iter().map(|header| {
            (
                PyBytes::new(py, header.name().as_bytes()),
                PyBytes::new(py, header.value().as_bytes()),
            )
        }),
    )?;
    PyTuple::new(
        py,
        [
            PyBytes::new(py, buffer.stream()).into_any(),
            headers.into_any(),
        ],
    )
}

fn header_range(data: &[u8], offset: usize, length: Option<usize>) -> PyResult<&[u8]> {
    let end = match length {
        Some(length) => offset.checked_add(length),
        None => Some(data.len()),
    };
    end.and_then(|end| data.get(offset..end))
        .ok_or_else(|| PyValueError::new_err("QPACK input range is out of bounds"))
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

                PyTuple::new(py, [stream_data, encoded_buffer])
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
    #[pyo3(signature = (max_table_capacity, blocked_streams, *, max_field_section_size=None))]
    pub fn py_new(
        max_table_capacity: u32,
        blocked_streams: u32,
        max_field_section_size: Option<usize>,
    ) -> Self {
        QpackDecoder {
            decoder: match max_field_section_size {
                Some(maximum) => Decoder::with_max_field_section_size(
                    max_table_capacity,
                    blocked_streams,
                    maximum,
                ),
                None => Decoder::new(max_table_capacity, blocked_streams),
            },
        }
    }

    pub fn feed_encoder<'a>(&mut self, py: Python<'a>, data: Bound<'_, PyBytes>) -> PyResult<()> {
        let input_data = data.as_bytes();

        let res = py.detach(|| self.decoder.feed(input_data));

        match res {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == DecoderErrorKind::FieldSectionTooLarge => Err(
                HeaderTooLarge::new_err("QPACK field section exceeds the configured limit"),
            ),
            Err(_) => Err(EncoderStreamError::new_err(
                "an error occurred while feeding data from encoder with qpack data",
            )),
        }
    }

    #[pyo3(signature = (stream_id, data, *, offset=0, length=None))]
    pub fn feed_header<'a>(
        &mut self,
        py: Python<'a>,
        stream_id: u64,
        data: Bound<'_, PyBytes>,
        offset: usize,
        length: Option<usize>,
    ) -> PyResult<Bound<'a, PyTuple>> {
        let input_data = header_range(data.as_bytes(), offset, length)?;
        if input_data.is_empty() {
            return Err(DecoderStreamError::new_err("Empty QPACK header block"));
        }

        let output = py.detach(|| self.decoder.decode(StreamId::new(stream_id), input_data));

        match output {
            Ok(DecoderOutput::Done(buffer)) => decoded_to_python(py, buffer),
            Ok(DecoderOutput::BlockedStream) => Err(StreamBlocked::new_err(
                "stream is blocked, need more data to pursue decoding",
            )),
            Err(error) if error.kind() == DecoderErrorKind::FieldSectionTooLarge => Err(
                HeaderTooLarge::new_err("QPACK field section exceeds the configured limit"),
            ),
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
        let res = py
            .detach(|| self.decoder.unblocked(StreamId::new(stream_id)))
            .ok_or_else(|| DecoderStreamError::new_err("stream id is unknown"))?;

        match res {
            Ok(DecoderOutput::Done(buffer)) => decoded_to_python(py, buffer),
            Ok(DecoderOutput::BlockedStream) => Err(StreamBlocked::new_err(
                "stream is blocked, need more data to pursue decoding",
            )),
            Err(error) if error.kind() == DecoderErrorKind::FieldSectionTooLarge => Err(
                HeaderTooLarge::new_err("QPACK field section exceeds the configured limit"),
            ),
            Err(_) => Err(DecoderStreamError::new_err(
                "an error occurred while decoding the stream qpack data",
            )),
        }
    }
}
