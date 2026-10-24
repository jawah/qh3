//! Borrow contiguous Python buffers for a synchronous copy into owned storage.

use std::ffi::{c_int, c_void};

use pyo3::exceptions::PyBufferError;
use pyo3::sync::critical_section::with_critical_section;
use pyo3::types::{PyAnyMethods, PyBytes, PyBytesMethods, PyMemoryView};
use pyo3::{ffi, Bound, PyAny, PyErr, PyResult};

extern "C" {
    // This function remains in the stable ABI, including Python 3.7. The
    // modern Py_buffer API only joined the stable ABI in Python 3.11.
    #[cfg_attr(PyPy, link_name = "PyPyObject_AsReadBuffer")]
    fn PyObject_AsReadBuffer(
        object: *mut ffi::PyObject,
        buffer: *mut *const c_void,
        length: *mut ffi::Py_ssize_t,
    ) -> c_int;
}

/// The callback must copy synchronously and must not retain the slice or call
/// Python code which could mutate its exporter. No payload conversion is made.
pub fn with_buffer<R>(
    value: &Bound<'_, PyAny>,
    copy: impl FnOnce(&[u8]) -> PyResult<R>,
) -> PyResult<R> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return copy(bytes.as_bytes());
    }

    // A private view pins the export even if the caller releases its own view.
    let view = PyMemoryView::from(value)?;
    // Dropping a Python reference does not promptly release an export on PyPy.
    #[cfg(PyPy)]
    struct ReleaseView<'a, 'py>(&'a Bound<'py, PyMemoryView>);
    #[cfg(PyPy)]
    impl Drop for ReleaseView<'_, '_> {
        fn drop(&mut self) {
            // This private view has no outstanding exports after AsReadBuffer.
            let _ = self.0.call_method0("release");
        }
    }
    #[cfg(PyPy)]
    let _release = ReleaseView(&view);
    // Older PyPy versions accept strided views in AsReadBuffer, potentially
    // exposing bytes outside the view. Check its layout before reading memory.
    #[cfg(PyPy)]
    if !view.getattr("c_contiguous")?.is_truthy()? {
        return Err(PyBufferError::new_err(
            "send data must be a C-contiguous buffer",
        ));
    }
    let owner = view.getattr("obj")?;
    let mut pointer = std::ptr::null();
    let mut length = 0;
    // SAFETY: the object is a live memoryview and both output pointers are valid.
    // Its export outlives this call, including after AsReadBuffer releases its
    // temporary export. CPython rejects non-contiguous views here; PyPy's
    // layout was checked explicitly above.
    if unsafe { PyObject_AsReadBuffer(view.as_ptr(), &mut pointer, &mut length) } != 0 {
        return Err(PyErr::fetch(value.py()));
    }
    let length =
        usize::try_from(length).map_err(|_| PyBufferError::new_err("Invalid buffer length"))?;
    if length != 0 && pointer.is_null() {
        return Err(PyBufferError::new_err("Invalid buffer pointer"));
    }
    with_critical_section(&owner, || {
        let data = if length == 0 {
            &[]
        } else {
            // SAFETY: the view pins a contiguous export of exactly `length`
            // bytes. It stays alive through the synchronous copy; callers must
            // not concurrently mutate the supplied buffer during the send call.
            unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }
        };
        copy(data)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyByteArray, PyByteArrayMethods, PySlice};
    use pyo3::Python;

    #[test]
    fn buffer_arguments_borrow_the_exporters_memory() {
        Python::initialize();
        Python::attach(|py| {
            let source = PyByteArray::new(py, b"abcdef");
            // SAFETY: this test holds the GIL and never modifies the array.
            let pointer = unsafe { source.as_bytes().as_ptr() };
            with_buffer(source.as_any(), |data| {
                assert_eq!(data.as_ptr(), pointer);
                assert_eq!(data, b"abcdef");
                Ok(())
            })
            .unwrap();
            let view = PyMemoryView::from(source.as_any()).unwrap();
            let sliced = view.get_item(PySlice::new(py, 1, 4, 1)).unwrap();
            with_buffer(&sliced, |data| {
                assert_eq!(data.as_ptr(), pointer.wrapping_add(1));
                assert_eq!(data, b"bcd");
                Ok(())
            })
            .unwrap();
        });
    }
}
