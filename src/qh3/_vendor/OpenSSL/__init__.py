import calendar
import datetime
import functools
import sys
import warnings
from base64 import b16encode
from functools import partial
from os import PathLike, fspath
from typing import (
    Any,
    Callable,
    Iterable,
    List,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

from cryptography import x509
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
)

binding = Binding()
_ffi = binding.ffi
_lib = binding.lib


# This is a special CFFI allocator that does not bother to zero its memory
# after allocation. This has vastly better performance on large allocations and
# so should be used whenever we don't need the memory zeroed out.
no_zero_allocator = _ffi.new_allocator(should_clear_after_alloc=False)
StrOrBytesPath = Union[str, bytes, PathLike]

# A marker object to observe whether some optional arguments are passed any
# value or not.
_UNSPECIFIED = object()
_TEXT_WARNING = "str for {0} is no longer accepted, use bytes"


def _byte_string(s: str) -> bytes:
    return s.encode("charmap")


def _path_bytes(s: StrOrBytesPath) -> bytes:
    """
    Convert a Python path to a :py:class:`bytes` for the path which can be
    passed into an OpenSSL API accepting a filename.

    :param s: A path (valid for os.fspath).

    :return: An instance of :py:class:`bytes`.
    """
    b = fspath(s)

    if isinstance(b, str):
        return b.encode(sys.getfilesystemencoding())
    else:
        return b


def text(charp: Any) -> str:
    """
    Get a native string type representing of the given CFFI ``char*`` object.

    :param charp: A C-style string represented using CFFI.

    :return: :class:`str`
    """
    if not charp:
        return ""
    return _ffi.string(charp).decode("utf-8")


def _exception_from_error_queue(exception_type: Type[Exception]) -> NoReturn:
    """
    Convert an OpenSSL library failure into a Python exception.

    When a call to the native OpenSSL library fails, this is usually signalled
    by the return value, and an error code is stored in an error queue
    associated with the current thread. The err library provides functions to
    obtain these error codes and textual error messages.
    """
    errors = []

    while True:
        error = _lib.ERR_get_error()
        if error == 0:
            break
        errors.append(
            (
                text(_lib.ERR_lib_error_string(error)),
                text(_lib.ERR_func_error_string(error)),
                text(_lib.ERR_reason_error_string(error)),
            )
        )

    raise exception_type(errors)


def _make_assert(error: Type[Exception]) -> Callable[[bool], Any]:
    """
    Create an assert function that uses :func:`exception_from_error_queue` to
    raise an exception wrapped by *error*.
    """

    def openssl_assert(ok: bool) -> None:
        """
        If *ok* is not True, retrieve the error from OpenSSL and raise it.
        """
        if ok is not True:
            _exception_from_error_queue(error)

    return openssl_assert


def _text_to_bytes_and_warn(label: str, obj: Any) -> Any:
    """
    If ``obj`` is text, emit a warning that it should be bytes instead and try
    to convert it to bytes automatically.

    :param str label: The name of the parameter from which ``obj`` was taken
        (so a developer can easily find the source of the problem and correct
        it).

    :return: If ``obj`` is the text string type, a ``bytes`` object giving the
        UTF-8 encoding of that text is returned.  Otherwise, ``obj`` itself is
        returned.
    """
    if isinstance(obj, str):
        warnings.warn(
            _TEXT_WARNING.format(label),
            category=DeprecationWarning,
            stacklevel=3,
        )
        return obj.encode("utf-8")
    return obj


__all__ = [
    "Error",
    "X509",
    "X509Store",
    "X509StoreContextError",
    "X509StoreContext",
]


_Key = Union[dsa.DSAPrivateKey, dsa.DSAPublicKey, rsa.RSAPrivateKey, rsa.RSAPublicKey]
PassphraseCallableT = Union[bytes, Callable[..., bytes]]


FILETYPE_PEM: int = _lib.SSL_FILETYPE_PEM
FILETYPE_ASN1: int = _lib.SSL_FILETYPE_ASN1

# TODO This was an API mistake.  OpenSSL has no such constant.
FILETYPE_TEXT = 2**16 - 1

TYPE_RSA: int = _lib.EVP_PKEY_RSA
TYPE_DSA: int = _lib.EVP_PKEY_DSA
TYPE_DH: int = _lib.EVP_PKEY_DH
TYPE_EC: int = _lib.EVP_PKEY_EC


class Error(Exception):
    """
    An error occurred in an `OpenSSL.crypto` API.
    """


_raise_current_error = partial(_exception_from_error_queue, Error)
_openssl_assert = _make_assert(Error)


def _untested_error(where: str) -> NoReturn:
    """
    An OpenSSL API failed somehow.  Additionally, the failure which was
    encountered isn't one that's exercised by the test suite so future behavior
    of pyOpenSSL is now somewhat less predictable.
    """
    raise RuntimeError("Unknown %s failure" % (where,))


def _new_mem_buf(buffer: Optional[bytes] = None) -> Any:
    """
    Allocate a new OpenSSL memory BIO.

    Arrange for the garbage collector to clean it up automatically.

    :param buffer: None or some bytes to use to put into the BIO so that they
        can be read out.
    """
    if buffer is None:
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        free = _lib.BIO_free
    else:
        data = _ffi.new("char[]", buffer)
        bio = _lib.BIO_new_mem_buf(data, len(buffer))

        # Keep the memory alive as long as the bio is alive!
        def free(bio: Any, ref: Any = data) -> Any:
            return _lib.BIO_free(bio)

    _openssl_assert(bio != _ffi.NULL)

    bio = _ffi.gc(bio, free)
    return bio


def _bio_to_string(bio: Any) -> bytes:
    """
    Copy the contents of an OpenSSL BIO object into a Python byte string.
    """
    result_buffer = _ffi.new("char**")
    buffer_length = _lib.BIO_get_mem_data(bio, result_buffer)
    return _ffi.buffer(result_buffer[0], buffer_length)[:]


def _set_asn1_time(boundary: Any, when: bytes) -> None:
    """
    The the time value of an ASN1 time object.

    @param boundary: An ASN1_TIME pointer (or an object safely
        castable to that type) which will have its value set.
    @param when: A string representation of the desired time value.

    @raise TypeError: If C{when} is not a L{bytes} string.
    @raise ValueError: If C{when} does not represent a time in the required
        format.
    @raise RuntimeError: If the time value cannot be set for some other
        (unspecified) reason.
    """
    if not isinstance(when, bytes):
        raise TypeError("when must be a byte string")
    # ASN1_TIME_set_string validates the string without writing anything
    # when the destination is NULL.
    _openssl_assert(boundary != _ffi.NULL)

    set_result = _lib.ASN1_TIME_set_string(boundary, when)
    if set_result == 0:
        raise ValueError("Invalid string")


def _new_asn1_time(when: bytes) -> Any:
    """
    Behaves like _set_asn1_time but returns a new ASN1_TIME object.

    @param when: A string representation of the desired time value.

    @raise TypeError: If C{when} is not a L{bytes} string.
    @raise ValueError: If C{when} does not represent a time in the required
        format.
    @raise RuntimeError: If the time value cannot be set for some other
        (unspecified) reason.
    """
    ret = _lib.ASN1_TIME_new()
    _openssl_assert(ret != _ffi.NULL)
    ret = _ffi.gc(ret, _lib.ASN1_TIME_free)
    _set_asn1_time(ret, when)
    return ret


def _get_asn1_time(timestamp: Any) -> Optional[bytes]:
    """
    Retrieve the time value of an ASN1 time object.

    @param timestamp: An ASN1_GENERALIZEDTIME* (or an object safely castable to
        that type) from which the time value will be retrieved.

    @return: The time value from C{timestamp} as a L{bytes} string in a certain
        format.  Or C{None} if the object contains no time value.
    """
    string_timestamp = _ffi.cast("ASN1_STRING*", timestamp)
    if _lib.ASN1_STRING_length(string_timestamp) == 0:
        return None
    elif _lib.ASN1_STRING_type(string_timestamp) == _lib.V_ASN1_GENERALIZEDTIME:
        return _ffi.string(_lib.ASN1_STRING_get0_data(string_timestamp))
    else:
        generalized_timestamp = _ffi.new("ASN1_GENERALIZEDTIME**")
        _lib.ASN1_TIME_to_generalizedtime(timestamp, generalized_timestamp)
        if generalized_timestamp[0] == _ffi.NULL:
            # This may happen:
            #   - if timestamp was not an ASN1_TIME
            #   - if allocating memory for the ASN1_GENERALIZEDTIME failed
            #   - if a copy of the time data from timestamp cannot be made for
            #     the newly allocated ASN1_GENERALIZEDTIME
            #
            # These are difficult to test.  cffi enforces the ASN1_TIME type.
            # Memory allocation failures are a pain to trigger
            # deterministically.
            _untested_error("ASN1_TIME_to_generalizedtime")
        else:
            string_timestamp = _ffi.cast("ASN1_STRING*", generalized_timestamp[0])
            string_data = _lib.ASN1_STRING_get0_data(string_timestamp)
            string_result = _ffi.string(string_data)
            _lib.ASN1_GENERALIZEDTIME_free(generalized_timestamp[0])
            return string_result


class _X509NameInvalidator:
    def __init__(self) -> None:
        self._names: List[X509Name] = []

    def add(self, name: "X509Name") -> None:
        self._names.append(name)

    def clear(self) -> None:
        for name in self._names:
            # Breaks the object, but also prevents UAF!
            del name._name


class PKey:
    """
    A class representing an DSA or RSA public key or key pair.
    """

    _only_public = False
    _initialized = True

    def __init__(self) -> None:
        pkey = _lib.EVP_PKEY_new()
        self._pkey = _ffi.gc(pkey, _lib.EVP_PKEY_free)
        self._initialized = False

    def to_cryptography_key(self) -> _Key:
        """
        Export as a ``cryptography`` key.

        :rtype: One of ``cryptography``'s `key interfaces`_.

        .. _key interfaces: https://cryptography.io/en/latest/hazmat/\
            primitives/asymmetric/rsa/#key-interfaces

        .. versionadded:: 16.1.0
        """
        from cryptography.hazmat.primitives.serialization import (
            load_der_private_key,
            load_der_public_key,
        )

        if self._only_public:
            der = dump_publickey(FILETYPE_ASN1, self)
            return load_der_public_key(der)  # type: ignore[return-value]
        else:
            der = dump_privatekey(FILETYPE_ASN1, self)
            return load_der_private_key(der, None)  # type: ignore[return-value]

    @classmethod
    def from_cryptography_key(cls, crypto_key: _Key) -> "PKey":
        """
        Construct based on a ``cryptography`` *crypto_key*.

        :param crypto_key: A ``cryptography`` key.
        :type crypto_key: One of ``cryptography``'s `key interfaces`_.

        :rtype: PKey

        .. versionadded:: 16.1.0
        """
        if not isinstance(
            crypto_key,
            (
                rsa.RSAPublicKey,
                rsa.RSAPrivateKey,
                dsa.DSAPublicKey,
                dsa.DSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            raise TypeError("Unsupported key type")

        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        if isinstance(crypto_key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
            return load_publickey(
                FILETYPE_ASN1,
                crypto_key.public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                ),
            )
        else:
            der = crypto_key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            return load_privatekey(FILETYPE_ASN1, der)

    def generate_key(self, type: int, bits: int) -> None:
        """
        Generate a key pair of the given type, with the given number of bits.

        This generates a key "into" the this object.

        :param type: The key type.
        :type type: :py:data:`TYPE_RSA` or :py:data:`TYPE_DSA`
        :param bits: The number of bits.
        :type bits: :py:data:`int` ``>= 0``
        :raises TypeError: If :py:data:`type` or :py:data:`bits` isn't
            of the appropriate type.
        :raises ValueError: If the number of bits isn't an integer of
            the appropriate size.
        :return: ``None``
        """
        if not isinstance(type, int):
            raise TypeError("type must be an integer")

        if not isinstance(bits, int):
            raise TypeError("bits must be an integer")

        if type == TYPE_RSA:
            if bits <= 0:
                raise ValueError("Invalid number of bits")

            # TODO Check error return
            exponent = _lib.BN_new()
            exponent = _ffi.gc(exponent, _lib.BN_free)
            _lib.BN_set_word(exponent, _lib.RSA_F4)

            rsa = _lib.RSA_new()

            result = _lib.RSA_generate_key_ex(rsa, bits, exponent, _ffi.NULL)
            _openssl_assert(result == 1)

            result = _lib.EVP_PKEY_assign_RSA(self._pkey, rsa)
            _openssl_assert(result == 1)

        elif type == TYPE_DSA:
            dsa = _lib.DSA_new()
            _openssl_assert(dsa != _ffi.NULL)

            dsa = _ffi.gc(dsa, _lib.DSA_free)
            res = _lib.DSA_generate_parameters_ex(
                dsa, bits, _ffi.NULL, 0, _ffi.NULL, _ffi.NULL, _ffi.NULL
            )
            _openssl_assert(res == 1)

            _openssl_assert(_lib.DSA_generate_key(dsa) == 1)
            _openssl_assert(_lib.EVP_PKEY_set1_DSA(self._pkey, dsa) == 1)
        else:
            raise Error("No such key type")

        self._initialized = True

    def check(self) -> bool:
        """
        Check the consistency of an RSA private key.

        This is the Python equivalent of OpenSSL's ``RSA_check_key``.

        :return: ``True`` if key is consistent.

        :raise OpenSSL.crypto.Error: if the key is inconsistent.

        :raise TypeError: if the key is of a type which cannot be checked.
            Only RSA keys can currently be checked.
        """
        if self._only_public:
            raise TypeError("public key only")

        if _lib.EVP_PKEY_type(self.type()) != _lib.EVP_PKEY_RSA:
            raise TypeError("Only RSA keys can currently be checked.")

        rsa = _lib.EVP_PKEY_get1_RSA(self._pkey)
        rsa = _ffi.gc(rsa, _lib.RSA_free)
        result = _lib.RSA_check_key(rsa)
        if result == 1:
            return True
        _raise_current_error()

    def type(self) -> int:
        """
        Returns the type of the key

        :return: The type of the key.
        """
        return _lib.EVP_PKEY_id(self._pkey)

    def bits(self) -> int:
        """
        Returns the number of bits of the key

        :return: The number of bits of the key.
        """
        return _lib.EVP_PKEY_bits(self._pkey)


@functools.total_ordering
class X509Name:
    """
    An X.509 Distinguished Name.

    :ivar countryName: The country of the entity.
    :ivar C: Alias for  :py:attr:`countryName`.

    :ivar stateOrProvinceName: The state or province of the entity.
    :ivar ST: Alias for :py:attr:`stateOrProvinceName`.

    :ivar localityName: The locality of the entity.
    :ivar L: Alias for :py:attr:`localityName`.

    :ivar organizationName: The organization name of the entity.
    :ivar O: Alias for :py:attr:`organizationName`.

    :ivar organizationalUnitName: The organizational unit of the entity.
    :ivar OU: Alias for :py:attr:`organizationalUnitName`

    :ivar commonName: The common name of the entity.
    :ivar CN: Alias for :py:attr:`commonName`.

    :ivar emailAddress: The e-mail address of the entity.
    """

    def __init__(self, name: "X509Name") -> None:
        """
        Create a new X509Name, copying the given X509Name instance.

        :param name: The name to copy.
        :type name: :py:class:`X509Name`
        """
        name = _lib.X509_NAME_dup(name._name)
        self._name: Any = _ffi.gc(name, _lib.X509_NAME_free)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            return super(X509Name, self).__setattr__(name, value)

        # Note: we really do not want str subclasses here, so we do not use
        # isinstance.
        if type(name) is not str:  # noqa: E721
            raise TypeError(
                "attribute name must be string, not '%.200s'" % (type(value).__name__,)
            )

        nid = _lib.OBJ_txt2nid(_byte_string(name))
        if nid == _lib.NID_undef:
            try:
                _raise_current_error()
            except Error:
                pass
            raise AttributeError("No such attribute")

        # If there's an old entry for this NID, remove it
        for i in range(_lib.X509_NAME_entry_count(self._name)):
            ent = _lib.X509_NAME_get_entry(self._name, i)
            ent_obj = _lib.X509_NAME_ENTRY_get_object(ent)
            ent_nid = _lib.OBJ_obj2nid(ent_obj)
            if nid == ent_nid:
                ent = _lib.X509_NAME_delete_entry(self._name, i)
                _lib.X509_NAME_ENTRY_free(ent)
                break

        if isinstance(value, str):
            value = value.encode("utf-8")

        add_result = _lib.X509_NAME_add_entry_by_NID(
            self._name, nid, _lib.MBSTRING_UTF8, value, -1, -1, 0
        )
        if not add_result:
            _raise_current_error()

    def __getattr__(self, name: str) -> Optional[str]:
        """
        Find attribute. An X509Name object has the following attributes:
        countryName (alias C), stateOrProvince (alias ST), locality (alias L),
        organization (alias O), organizationalUnit (alias OU), commonName
        (alias CN) and more...
        """
        nid = _lib.OBJ_txt2nid(_byte_string(name))
        if nid == _lib.NID_undef:
            # This is a bit weird.  OBJ_txt2nid indicated failure, but it seems
            # a lower level function, a2d_ASN1_OBJECT, also feels the need to
            # push something onto the error queue.  If we don't clean that up
            # now, someone else will bump into it later and be quite confused.
            # See lp#314814.
            try:
                _raise_current_error()
            except Error:
                pass
            raise AttributeError("No such attribute")

        entry_index = _lib.X509_NAME_get_index_by_NID(self._name, nid, -1)
        if entry_index == -1:
            return None

        entry = _lib.X509_NAME_get_entry(self._name, entry_index)
        data = _lib.X509_NAME_ENTRY_get_data(entry)

        result_buffer = _ffi.new("unsigned char**")
        data_length = _lib.ASN1_STRING_to_UTF8(result_buffer, data)
        _openssl_assert(data_length >= 0)

        try:
            result = _ffi.buffer(result_buffer[0], data_length)[:].decode("utf-8")
        finally:
            # XXX untested
            _lib.OPENSSL_free(result_buffer[0])
        return result

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, X509Name):
            return NotImplemented

        return _lib.X509_NAME_cmp(self._name, other._name) == 0

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, X509Name):
            return NotImplemented

        return _lib.X509_NAME_cmp(self._name, other._name) < 0

    def __repr__(self) -> str:
        """
        String representation of an X509Name
        """
        result_buffer = _ffi.new("char[]", 512)
        format_result = _lib.X509_NAME_oneline(
            self._name, result_buffer, len(result_buffer)
        )
        _openssl_assert(format_result != _ffi.NULL)

        return "<X509Name object '%s'>" % (_ffi.string(result_buffer).decode("utf-8"),)

    def hash(self) -> int:
        """
        Return an integer representation of the first four bytes of the
        MD5 digest of the DER representation of the name.

        This is the Python equivalent of OpenSSL's ``X509_NAME_hash``.

        :return: The (integer) hash of this name.
        :rtype: :py:class:`int`
        """
        return _lib.X509_NAME_hash(self._name)

    def der(self) -> bytes:
        """
        Return the DER encoding of this name.

        :return: The DER encoded form of this name.
        :rtype: :py:class:`bytes`
        """
        result_buffer = _ffi.new("unsigned char**")
        encode_result = _lib.i2d_X509_NAME(self._name, result_buffer)
        _openssl_assert(encode_result >= 0)

        string_result = _ffi.buffer(result_buffer[0], encode_result)[:]
        _lib.OPENSSL_free(result_buffer[0])
        return string_result

    def get_components(self) -> List[Tuple[bytes, bytes]]:
        """
        Returns the components of this name, as a sequence of 2-tuples.

        :return: The components of this name.
        :rtype: :py:class:`list` of ``name, value`` tuples.
        """
        result = []
        for i in range(_lib.X509_NAME_entry_count(self._name)):
            ent = _lib.X509_NAME_get_entry(self._name, i)

            fname = _lib.X509_NAME_ENTRY_get_object(ent)
            fval = _lib.X509_NAME_ENTRY_get_data(ent)

            nid = _lib.OBJ_obj2nid(fname)
            name = _lib.OBJ_nid2sn(nid)

            # ffi.string does not handle strings containing NULL bytes
            # (which may have been generated by old, broken software)
            value = _ffi.buffer(
                _lib.ASN1_STRING_get0_data(fval), _lib.ASN1_STRING_length(fval)
            )[:]
            result.append((_ffi.string(name), value))

        return result


class X509Extension:
    """
    An X.509 v3 certificate extension.
    """

    def __init__(
        self,
        type_name: bytes,
        critical: bool,
        value: bytes,
        subject: Optional["X509"] = None,
        issuer: Optional["X509"] = None,
    ) -> None:
        """
        Initializes an X509 extension.

        :param type_name: The name of the type of extension_ to create.
        :type type_name: :py:data:`bytes`

        :param bool critical: A flag indicating whether this is a critical
            extension.

        :param value: The OpenSSL textual representation of the extension's
            value.
        :type value: :py:data:`bytes`

        :param subject: Optional X509 certificate to use as subject.
        :type subject: :py:class:`X509`

        :param issuer: Optional X509 certificate to use as issuer.
        :type issuer: :py:class:`X509`

        .. _extension: https://www.openssl.org/docs/manmaster/man5/
            x509v3_config.html#STANDARD-EXTENSIONS
        """
        ctx = _ffi.new("X509V3_CTX*")

        # A context is necessary for any extension which uses the r2i
        # conversion method.  That is, X509V3_EXT_nconf may segfault if passed
        # a NULL ctx. Start off by initializing most of the fields to NULL.
        _lib.X509V3_set_ctx(ctx, _ffi.NULL, _ffi.NULL, _ffi.NULL, _ffi.NULL, 0)

        # We have no configuration database - but perhaps we should (some
        # extensions may require it).
        _lib.X509V3_set_ctx_nodb(ctx)

        # Initialize the subject and issuer, if appropriate.  ctx is a local,
        # and as far as I can tell none of the X509V3_* APIs invoked here steal
        # any references, so no need to mess with reference counts or
        # duplicates.
        if issuer is not None:
            if not isinstance(issuer, X509):
                raise TypeError("issuer must be an X509 instance")
            ctx.issuer_cert = issuer._x509
        if subject is not None:
            if not isinstance(subject, X509):
                raise TypeError("subject must be an X509 instance")
            ctx.subject_cert = subject._x509

        if critical:
            # There are other OpenSSL APIs which would let us pass in critical
            # separately, but they're harder to use, and since value is already
            # a pile of crappy junk smuggling a ton of utterly important
            # structured data, what's the point of trying to avoid nasty stuff
            # with strings? (However, X509V3_EXT_i2d in particular seems like
            # it would be a better API to invoke.  I do not know where to get
            # the ext_struc it desires for its last parameter, though.)
            value = b"critical," + value

        extension = _lib.X509V3_EXT_nconf(_ffi.NULL, ctx, type_name, value)
        if extension == _ffi.NULL:
            _raise_current_error()
        self._extension = _ffi.gc(extension, _lib.X509_EXTENSION_free)

    @property
    def _nid(self) -> Any:
        return _lib.OBJ_obj2nid(_lib.X509_EXTENSION_get_object(self._extension))

    _prefixes = {
        _lib.GEN_EMAIL: "email",
        _lib.GEN_DNS: "DNS",
        _lib.GEN_URI: "URI",
    }

    def _subjectAltNameString(self) -> str:
        names = _ffi.cast("GENERAL_NAMES*", _lib.X509V3_EXT_d2i(self._extension))

        names = _ffi.gc(names, _lib.GENERAL_NAMES_free)
        parts = []
        for i in range(_lib.sk_GENERAL_NAME_num(names)):
            name = _lib.sk_GENERAL_NAME_value(names, i)
            try:
                label = self._prefixes[name.type]
            except KeyError:
                bio = _new_mem_buf()
                _lib.GENERAL_NAME_print(bio, name)
                parts.append(_bio_to_string(bio).decode("utf-8"))
            else:
                value = _ffi.buffer(name.d.ia5.data, name.d.ia5.length)[:].decode(
                    "utf-8"
                )
                parts.append(label + ":" + value)
        return ", ".join(parts)

    def __str__(self) -> str:
        """
        :return: a nice text representation of the extension
        """
        if _lib.NID_subject_alt_name == self._nid:
            return self._subjectAltNameString()

        bio = _new_mem_buf()
        print_result = _lib.X509V3_EXT_print(bio, self._extension, 0, 0)
        _openssl_assert(print_result != 0)

        return _bio_to_string(bio).decode("utf-8")

    def get_critical(self) -> bool:
        """
        Returns the critical field of this X.509 extension.

        :return: The critical field.
        """
        return _lib.X509_EXTENSION_get_critical(self._extension)

    def get_short_name(self) -> bytes:
        """
        Returns the short type name of this X.509 extension.

        The result is a byte string such as :py:const:`b"basicConstraints"`.

        :return: The short type name.
        :rtype: :py:data:`bytes`

        .. versionadded:: 0.12
        """
        obj = _lib.X509_EXTENSION_get_object(self._extension)
        nid = _lib.OBJ_obj2nid(obj)
        # OpenSSL 3.1.0 has a bug where nid2sn returns NULL for NIDs that
        # previously returned UNDEF. This is a workaround for that issue.
        # https://github.com/openssl/openssl/commit/908ba3ed9adbb3df90f76
        buf = _lib.OBJ_nid2sn(nid)
        if buf != _ffi.NULL:
            return _ffi.string(buf)
        else:
            return b"UNDEF"

    def get_data(self) -> bytes:
        """
        Returns the data of the X509 extension, encoded as ASN.1.

        :return: The ASN.1 encoded data of this X509 extension.
        :rtype: :py:data:`bytes`

        .. versionadded:: 0.12
        """
        octet_result = _lib.X509_EXTENSION_get_data(self._extension)
        string_result = _ffi.cast("ASN1_STRING*", octet_result)
        char_result = _lib.ASN1_STRING_get0_data(string_result)
        result_length = _lib.ASN1_STRING_length(string_result)
        return _ffi.buffer(char_result, result_length)[:]


class X509:
    """
    An X.509 certificate.
    """

    def __init__(self) -> None:
        x509 = _lib.X509_new()
        _openssl_assert(x509 != _ffi.NULL)
        self._x509 = _ffi.gc(x509, _lib.X509_free)

        self._issuer_invalidator = _X509NameInvalidator()
        self._subject_invalidator = _X509NameInvalidator()

    @classmethod
    def _from_raw_x509_ptr(cls, x509: Any) -> "X509":
        cert = cls.__new__(cls)
        cert._x509 = _ffi.gc(x509, _lib.X509_free)
        cert._issuer_invalidator = _X509NameInvalidator()
        cert._subject_invalidator = _X509NameInvalidator()
        return cert

    def to_cryptography(self) -> x509.Certificate:
        """
        Export as a ``cryptography`` certificate.

        :rtype: ``cryptography.x509.Certificate``

        .. versionadded:: 17.1.0
        """
        from cryptography.x509 import load_der_x509_certificate

        der = dump_certificate(FILETYPE_ASN1, self)
        return load_der_x509_certificate(der)

    @classmethod
    def from_cryptography(cls, crypto_cert: x509.Certificate) -> "X509":
        """
        Construct based on a ``cryptography`` *crypto_cert*.

        :param crypto_key: A ``cryptography`` X.509 certificate.
        :type crypto_key: ``cryptography.x509.Certificate``

        :rtype: X509

        .. versionadded:: 17.1.0
        """
        if not isinstance(crypto_cert, x509.Certificate):
            raise TypeError("Must be a certificate")

        from cryptography.hazmat.primitives.serialization import Encoding

        der = crypto_cert.public_bytes(Encoding.DER)
        return load_certificate(FILETYPE_ASN1, der)

    def set_version(self, version: int) -> None:
        """
        Set the version number of the certificate. Note that the
        version value is zero-based, eg. a value of 0 is V1.

        :param version: The version number of the certificate.
        :type version: :py:class:`int`

        :return: ``None``
        """
        if not isinstance(version, int):
            raise TypeError("version must be an integer")

        _openssl_assert(_lib.X509_set_version(self._x509, version) == 1)

    def get_version(self) -> int:
        """
        Return the version number of the certificate.

        :return: The version number of the certificate.
        :rtype: :py:class:`int`
        """
        return _lib.X509_get_version(self._x509)

    def get_pubkey(self) -> PKey:
        """
        Get the public key of the certificate.

        :return: The public key.
        :rtype: :py:class:`PKey`
        """
        pkey = PKey.__new__(PKey)
        pkey._pkey = _lib.X509_get_pubkey(self._x509)
        if pkey._pkey == _ffi.NULL:
            _raise_current_error()
        pkey._pkey = _ffi.gc(pkey._pkey, _lib.EVP_PKEY_free)
        pkey._only_public = True
        return pkey

    def set_pubkey(self, pkey: PKey) -> None:
        """
        Set the public key of the certificate.

        :param pkey: The public key.
        :type pkey: :py:class:`PKey`

        :return: :py:data:`None`
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")

        set_result = _lib.X509_set_pubkey(self._x509, pkey._pkey)
        _openssl_assert(set_result == 1)

    def sign(self, pkey: PKey, digest: str) -> None:
        """
        Sign the certificate with this key and digest type.

        :param pkey: The key to sign with.
        :type pkey: :py:class:`PKey`

        :param digest: The name of the message digest to use.
        :type digest: :py:class:`str`

        :return: :py:data:`None`
        """
        if not isinstance(pkey, PKey):
            raise TypeError("pkey must be a PKey instance")

        if pkey._only_public:
            raise ValueError("Key only has public part")

        if not pkey._initialized:
            raise ValueError("Key is uninitialized")

        evp_md = _lib.EVP_get_digestbyname(_byte_string(digest))
        if evp_md == _ffi.NULL:
            raise ValueError("No such digest method")

        sign_result = _lib.X509_sign(self._x509, pkey._pkey, evp_md)
        _openssl_assert(sign_result > 0)

    def get_signature_algorithm(self) -> bytes:
        """
        Return the signature algorithm used in the certificate.

        :return: The name of the algorithm.
        :rtype: :py:class:`bytes`

        :raises ValueError: If the signature algorithm is undefined.

        .. versionadded:: 0.13
        """
        algor = _lib.X509_get0_tbs_sigalg(self._x509)
        nid = _lib.OBJ_obj2nid(algor.algorithm)
        if nid == _lib.NID_undef:
            raise ValueError("Undefined signature algorithm")
        return _ffi.string(_lib.OBJ_nid2ln(nid))

    def digest(self, digest_name: str) -> bytes:
        """
        Return the digest of the X509 object.

        :param digest_name: The name of the digest algorithm to use.
        :type digest_name: :py:class:`str`

        :return: The digest of the object, formatted as
            :py:const:`b":"`-delimited hex pairs.
        :rtype: :py:class:`bytes`
        """
        digest = _lib.EVP_get_digestbyname(_byte_string(digest_name))
        if digest == _ffi.NULL:
            raise ValueError("No such digest method")

        result_buffer = _ffi.new("unsigned char[]", _lib.EVP_MAX_MD_SIZE)
        result_length = _ffi.new("unsigned int[]", 1)
        result_length[0] = len(result_buffer)

        digest_result = _lib.X509_digest(
            self._x509, digest, result_buffer, result_length
        )
        _openssl_assert(digest_result == 1)

        return b":".join(
            [
                b16encode(ch).upper()
                for ch in _ffi.buffer(result_buffer, result_length[0])
            ]
        )

    def subject_name_hash(self) -> bytes:
        """
        Return the hash of the X509 subject.

        :return: The hash of the subject.
        :rtype: :py:class:`bytes`
        """
        return _lib.X509_subject_name_hash(self._x509)

    def set_serial_number(self, serial: int) -> None:
        """
        Set the serial number of the certificate.

        :param serial: The new serial number.
        :type serial: :py:class:`int`

        :return: :py:data`None`
        """
        if not isinstance(serial, int):
            raise TypeError("serial must be an integer")

        hex_serial = hex(serial)[2:]
        hex_serial_bytes = hex_serial.encode("ascii")

        bignum_serial = _ffi.new("BIGNUM**")

        # BN_hex2bn stores the result in &bignum.  Unless it doesn't feel like
        # it.  If bignum is still NULL after this call, then the return value
        # is actually the result.  I hope.  -exarkun
        small_serial = _lib.BN_hex2bn(bignum_serial, hex_serial_bytes)

        if bignum_serial[0] == _ffi.NULL:
            set_result = _lib.ASN1_INTEGER_set(
                _lib.X509_get_serialNumber(self._x509), small_serial
            )
            if set_result:
                # TODO Not tested
                _raise_current_error()
        else:
            asn1_serial = _lib.BN_to_ASN1_INTEGER(bignum_serial[0], _ffi.NULL)
            _lib.BN_free(bignum_serial[0])
            if asn1_serial == _ffi.NULL:
                # TODO Not tested
                _raise_current_error()
            asn1_serial = _ffi.gc(asn1_serial, _lib.ASN1_INTEGER_free)
            set_result = _lib.X509_set_serialNumber(self._x509, asn1_serial)
            _openssl_assert(set_result == 1)

    def get_serial_number(self) -> int:
        """
        Return the serial number of this certificate.

        :return: The serial number.
        :rtype: int
        """
        asn1_serial = _lib.X509_get_serialNumber(self._x509)
        bignum_serial = _lib.ASN1_INTEGER_to_BN(asn1_serial, _ffi.NULL)
        try:
            hex_serial = _lib.BN_bn2hex(bignum_serial)
            try:
                hexstring_serial = _ffi.string(hex_serial)
                serial = int(hexstring_serial, 16)
                return serial
            finally:
                _lib.OPENSSL_free(hex_serial)
        finally:
            _lib.BN_free(bignum_serial)

    def gmtime_adj_notAfter(self, amount: int) -> None:
        """
        Adjust the time stamp on which the certificate stops being valid.

        :param int amount: The number of seconds by which to adjust the
            timestamp.
        :return: ``None``
        """
        if not isinstance(amount, int):
            raise TypeError("amount must be an integer")

        notAfter = _lib.X509_getm_notAfter(self._x509)
        _lib.X509_gmtime_adj(notAfter, amount)

    def gmtime_adj_notBefore(self, amount: int) -> None:
        """
        Adjust the timestamp on which the certificate starts being valid.

        :param amount: The number of seconds by which to adjust the timestamp.
        :return: ``None``
        """
        if not isinstance(amount, int):
            raise TypeError("amount must be an integer")

        notBefore = _lib.X509_getm_notBefore(self._x509)
        _lib.X509_gmtime_adj(notBefore, amount)

    def has_expired(self) -> bool:
        """
        Check whether the certificate has expired.

        :return: ``True`` if the certificate has expired, ``False`` otherwise.
        :rtype: bool
        """
        time_bytes = self.get_notAfter()
        if time_bytes is None:
            raise ValueError("Unable to determine notAfter")
        time_string = time_bytes.decode("utf-8")
        not_after = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")

        return not_after < datetime.datetime.now(datetime.timezone.utc)

    def _get_boundary_time(self, which: Any) -> Optional[bytes]:
        return _get_asn1_time(which(self._x509))

    def get_notBefore(self) -> Optional[bytes]:
        """
        Get the timestamp at which the certificate starts being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :return: A timestamp string, or ``None`` if there is none.
        :rtype: bytes or NoneType
        """
        return self._get_boundary_time(_lib.X509_getm_notBefore)

    def _set_boundary_time(self, which: Callable[..., Any], when: bytes) -> None:
        return _set_asn1_time(which(self._x509), when)

    def set_notBefore(self, when: bytes) -> None:
        """
        Set the timestamp at which the certificate starts being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        return self._set_boundary_time(_lib.X509_getm_notBefore, when)

    def get_notAfter(self) -> Optional[bytes]:
        """
        Get the timestamp at which the certificate stops being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :return: A timestamp string, or ``None`` if there is none.
        :rtype: bytes or NoneType
        """
        return self._get_boundary_time(_lib.X509_getm_notAfter)

    def set_notAfter(self, when: bytes) -> None:
        """
        Set the timestamp at which the certificate stops being valid.

        The timestamp is formatted as an ASN.1 TIME::

            YYYYMMDDhhmmssZ

        :param bytes when: A timestamp string.
        :return: ``None``
        """
        return self._set_boundary_time(_lib.X509_getm_notAfter, when)

    def _get_name(self, which: Any) -> X509Name:
        name = X509Name.__new__(X509Name)
        name._name = which(self._x509)
        _openssl_assert(name._name != _ffi.NULL)

        # The name is owned by the X509 structure.  As long as the X509Name
        # Python object is alive, keep the X509 Python object alive.
        name._owner = self

        return name

    def _set_name(self, which: Any, name: X509Name) -> None:
        if not isinstance(name, X509Name):
            raise TypeError("name must be an X509Name")
        set_result = which(self._x509, name._name)
        _openssl_assert(set_result == 1)

    def get_issuer(self) -> X509Name:
        """
        Return the issuer of this certificate.

        This creates a new :class:`X509Name` that wraps the underlying issuer
        name field on the certificate. Modifying it will modify the underlying
        certificate, and will have the effect of modifying any other
        :class:`X509Name` that refers to this issuer.

        :return: The issuer of this certificate.
        :rtype: :class:`X509Name`
        """
        name = self._get_name(_lib.X509_get_issuer_name)
        self._issuer_invalidator.add(name)
        return name

    def set_issuer(self, issuer: X509Name) -> None:
        """
        Set the issuer of this certificate.

        :param issuer: The issuer.
        :type issuer: :py:class:`X509Name`

        :return: ``None``
        """
        self._set_name(_lib.X509_set_issuer_name, issuer)
        self._issuer_invalidator.clear()

    def get_subject(self) -> X509Name:
        """
        Return the subject of this certificate.

        This creates a new :class:`X509Name` that wraps the underlying subject
        name field on the certificate. Modifying it will modify the underlying
        certificate, and will have the effect of modifying any other
        :class:`X509Name` that refers to this subject.

        :return: The subject of this certificate.
        :rtype: :class:`X509Name`
        """
        name = self._get_name(_lib.X509_get_subject_name)
        self._subject_invalidator.add(name)
        return name

    def set_subject(self, subject: X509Name) -> None:
        """
        Set the subject of this certificate.

        :param subject: The subject.
        :type subject: :py:class:`X509Name`

        :return: ``None``
        """
        self._set_name(_lib.X509_set_subject_name, subject)
        self._subject_invalidator.clear()

    def get_extension_count(self) -> int:
        """
        Get the number of extensions on this certificate.

        :return: The number of extensions.
        :rtype: :py:class:`int`

        .. versionadded:: 0.12
        """
        return _lib.X509_get_ext_count(self._x509)

    def add_extensions(self, extensions: Iterable[X509Extension]) -> None:
        """
        Add extensions to the certificate.

        :param extensions: The extensions to add.
        :type extensions: An iterable of :py:class:`X509Extension` objects.
        :return: ``None``
        """
        for ext in extensions:
            if not isinstance(ext, X509Extension):
                raise ValueError("One of the elements is not an X509Extension")

            add_result = _lib.X509_add_ext(self._x509, ext._extension, -1)
            if not add_result:
                _raise_current_error()

    def get_extension(self, index: int) -> X509Extension:
        """
        Get a specific extension of the certificate by index.

        Extensions on a certificate are kept in order. The index
        parameter selects which extension will be returned.

        :param int index: The index of the extension to retrieve.
        :return: The extension at the specified index.
        :rtype: :py:class:`X509Extension`
        :raises IndexError: If the extension index was out of bounds.

        .. versionadded:: 0.12
        """
        ext = X509Extension.__new__(X509Extension)
        ext._extension = _lib.X509_get_ext(self._x509, index)
        if ext._extension == _ffi.NULL:
            raise IndexError("extension index out of bounds")

        extension = _lib.X509_EXTENSION_dup(ext._extension)
        ext._extension = _ffi.gc(extension, _lib.X509_EXTENSION_free)
        return ext


class X509StoreFlags:
    """
    Flags for X509 verification, used to change the behavior of
    :class:`X509Store`.

    See `OpenSSL Verification Flags`_ for details.

    .. _OpenSSL Verification Flags:
        https://www.openssl.org/docs/manmaster/man3/X509_VERIFY_PARAM_set_flags.html
    """

    CRL_CHECK: int = _lib.X509_V_FLAG_CRL_CHECK
    CRL_CHECK_ALL: int = _lib.X509_V_FLAG_CRL_CHECK_ALL
    IGNORE_CRITICAL: int = _lib.X509_V_FLAG_IGNORE_CRITICAL
    X509_STRICT: int = _lib.X509_V_FLAG_X509_STRICT
    ALLOW_PROXY_CERTS: int = _lib.X509_V_FLAG_ALLOW_PROXY_CERTS
    POLICY_CHECK: int = _lib.X509_V_FLAG_POLICY_CHECK
    EXPLICIT_POLICY: int = _lib.X509_V_FLAG_EXPLICIT_POLICY
    INHIBIT_MAP: int = _lib.X509_V_FLAG_INHIBIT_MAP
    CHECK_SS_SIGNATURE: int = _lib.X509_V_FLAG_CHECK_SS_SIGNATURE
    PARTIAL_CHAIN: int = _lib.X509_V_FLAG_PARTIAL_CHAIN


class X509Store:
    """
    An X.509 store.

    An X.509 store is used to describe a context in which to verify a
    certificate. A description of a context may include a set of certificates
    to trust, a set of certificate revocation lists, verification flags and
    more.

    An X.509 store, being only a description, cannot be used by itself to
    verify a certificate. To carry out the actual verification process, see
    :class:`X509StoreContext`.
    """

    def __init__(self) -> None:
        store = _lib.X509_STORE_new()
        self._store = _ffi.gc(store, _lib.X509_STORE_free)

    def add_cert(self, cert: X509) -> None:
        """
        Adds a trusted certificate to this store.

        Adding a certificate with this method adds this certificate as a
        *trusted* certificate.

        :param X509 cert: The certificate to add to this store.

        :raises TypeError: If the certificate is not an :class:`X509`.

        :raises OpenSSL.crypto.Error: If OpenSSL was unhappy with your
            certificate.

        :return: ``None`` if the certificate was added successfully.
        """
        if not isinstance(cert, X509):
            raise TypeError()

        res = _lib.X509_STORE_add_cert(self._store, cert._x509)
        _openssl_assert(res == 1)

    def set_flags(self, flags: int) -> None:
        """
        Set verification flags to this store.

        Verification flags can be combined by oring them together.

        .. note::

          Setting a verification flag sometimes requires clients to add
          additional information to the store, otherwise a suitable error will
          be raised.

          For example, in setting flags to enable CRL checking a
          suitable CRL must be added to the store otherwise an error will be
          raised.

        .. versionadded:: 16.1.0

        :param int flags: The verification flags to set on this store.
            See :class:`X509StoreFlags` for available constants.
        :return: ``None`` if the verification flags were successfully set.
        """
        _openssl_assert(_lib.X509_STORE_set_flags(self._store, flags) != 0)

    def set_time(self, vfy_time: datetime.datetime) -> None:
        """
        Set the time against which the certificates are verified.

        Normally the current time is used.

        .. note::

          For example, you can determine if a certificate was valid at a given
          time.

        .. versionadded:: 17.0.0

        :param datetime vfy_time: The verification time to set on this store.
        :return: ``None`` if the verification time was successfully set.
        """
        param = _lib.X509_VERIFY_PARAM_new()
        param = _ffi.gc(param, _lib.X509_VERIFY_PARAM_free)

        _lib.X509_VERIFY_PARAM_set_time(param, calendar.timegm(vfy_time.timetuple()))
        _openssl_assert(_lib.X509_STORE_set1_param(self._store, param) != 0)

    def load_locations(
        self, cafile: StrOrBytesPath, capath: Optional[StrOrBytesPath] = None
    ) -> None:
        """
        Let X509Store know where we can find trusted certificates for the
        certificate chain.  Note that the certificates have to be in PEM
        format.

        If *capath* is passed, it must be a directory prepared using the
        ``c_rehash`` tool included with OpenSSL.  Either, but not both, of
        *cafile* or *capath* may be ``None``.

        .. note::

          Both *cafile* and *capath* may be set simultaneously.

          Call this method multiple times to add more than one location.
          For example, CA certificates, and certificate revocation list bundles
          may be passed in *cafile* in subsequent calls to this method.

        .. versionadded:: 20.0

        :param cafile: In which file we can find the certificates (``bytes`` or
                       ``unicode``).
        :param capath: In which directory we can find the certificates
                       (``bytes`` or ``unicode``).

        :return: ``None`` if the locations were set successfully.

        :raises OpenSSL.crypto.Error: If both *cafile* and *capath* is ``None``
            or the locations could not be set for any reason.

        """
        if cafile is None:
            cafile = _ffi.NULL
        else:
            cafile = _path_bytes(cafile)

        if capath is None:
            capath = _ffi.NULL
        else:
            capath = _path_bytes(capath)

        load_result = _lib.X509_STORE_load_locations(self._store, cafile, capath)
        if not load_result:
            _raise_current_error()


class X509StoreContextError(Exception):
    """
    An exception raised when an error occurred while verifying a certificate
    using `OpenSSL.X509StoreContext.verify_certificate`.

    :ivar certificate: The certificate which caused verificate failure.
    :type certificate: :class:`X509`
    """

    def __init__(self, message: str, errors: List[Any], certificate: X509) -> None:
        super(X509StoreContextError, self).__init__(message)
        self.errors = errors
        self.certificate = certificate


class X509StoreContext:
    """
    An X.509 store context.

    An X.509 store context is used to carry out the actual verification process
    of a certificate in a described context. For describing such a context, see
    :class:`X509Store`.

    :ivar _store_ctx: The underlying X509_STORE_CTX structure used by this
        instance.  It is dynamically allocated and automatically garbage
        collected.
    :ivar _store: See the ``store`` ``__init__`` parameter.
    :ivar _cert: See the ``certificate`` ``__init__`` parameter.
    :ivar _chain: See the ``chain`` ``__init__`` parameter.
    :param X509Store store: The certificates which will be trusted for the
        purposes of any verifications.
    :param X509 certificate: The certificate to be verified.
    :param chain: List of untrusted certificates that may be used for building
        the certificate chain. May be ``None``.
    :type chain: :class:`list` of :class:`X509`
    """

    def __init__(
        self,
        store: X509Store,
        certificate: X509,
        chain: Optional[Sequence[X509]] = None,
    ) -> None:
        store_ctx = _lib.X509_STORE_CTX_new()
        self._store_ctx = _ffi.gc(store_ctx, _lib.X509_STORE_CTX_free)
        self._store = store
        self._cert = certificate
        self._chain = self._build_certificate_stack(chain)
        # Make the store context available for use after instantiating this
        # class by initializing it now. Per testing, subsequent calls to
        # :meth:`_init` have no adverse affect.
        self._init()

    @staticmethod
    def _build_certificate_stack(
        certificates: Optional[Sequence[X509]],
    ) -> None:
        def cleanup(s: Any) -> None:
            # Equivalent to sk_X509_pop_free, but we don't
            # currently have a CFFI binding for that available
            for i in range(_lib.sk_X509_num(s)):
                x = _lib.sk_X509_value(s, i)
                _lib.X509_free(x)
            _lib.sk_X509_free(s)

        if certificates is None or len(certificates) == 0:
            return _ffi.NULL

        stack = _lib.sk_X509_new_null()
        _openssl_assert(stack != _ffi.NULL)
        stack = _ffi.gc(stack, cleanup)

        for cert in certificates:
            if not isinstance(cert, X509):
                raise TypeError("One of the elements is not an X509 instance")

            _openssl_assert(_lib.X509_up_ref(cert._x509) > 0)
            if _lib.sk_X509_push(stack, cert._x509) <= 0:
                _lib.X509_free(cert._x509)
                _raise_current_error()

        return stack

    def _init(self) -> None:
        """
        Set up the store context for a subsequent verification operation.

        Calling this method more than once without first calling
        :meth:`_cleanup` will leak memory.
        """
        ret = _lib.X509_STORE_CTX_init(
            self._store_ctx, self._store._store, self._cert._x509, self._chain
        )
        if ret <= 0:
            _raise_current_error()

    def _cleanup(self) -> None:
        """
        Internally cleans up the store context.

        The store context can then be reused with a new call to :meth:`_init`.
        """
        _lib.X509_STORE_CTX_cleanup(self._store_ctx)

    def _exception_from_context(self) -> X509StoreContextError:
        """
        Convert an OpenSSL native context error failure into a Python
        exception.

        When a call to native OpenSSL X509_verify_cert fails, additional
        information about the failure can be obtained from the store context.
        """
        message = _ffi.string(
            _lib.X509_verify_cert_error_string(
                _lib.X509_STORE_CTX_get_error(self._store_ctx)
            )
        ).decode("utf-8")
        errors = [
            _lib.X509_STORE_CTX_get_error(self._store_ctx),
            _lib.X509_STORE_CTX_get_error_depth(self._store_ctx),
            message,
        ]
        # A context error should always be associated with a certificate, so we
        # expect this call to never return :class:`None`.
        _x509 = _lib.X509_STORE_CTX_get_current_cert(self._store_ctx)
        _cert = _lib.X509_dup(_x509)
        pycert = X509._from_raw_x509_ptr(_cert)
        return X509StoreContextError(message, errors, pycert)

    def set_store(self, store: X509Store) -> None:
        """
        Set the context's X.509 store.

        .. versionadded:: 0.15

        :param X509Store store: The store description which will be used for
            the purposes of any *future* verifications.
        """
        self._store = store

    def verify_certificate(self) -> None:
        """
        Verify a certificate in a context.

        .. versionadded:: 0.15

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.
        """
        # Always re-initialize the store context in case
        # :meth:`verify_certificate` is called multiple times.
        #
        # :meth:`_init` is called in :meth:`__init__` so _cleanup is called
        # before _init to ensure memory is not leaked.
        self._cleanup()
        self._init()
        ret = _lib.X509_verify_cert(self._store_ctx)
        self._cleanup()
        if ret <= 0:
            raise self._exception_from_context()

    def get_verified_chain(self) -> List[X509]:
        """
        Verify a certificate in a context and return the complete validated
        chain.

        :raises X509StoreContextError: If an error occurred when validating a
          certificate in the context. Sets ``certificate`` attribute to
          indicate which certificate caused the error.

        .. versionadded:: 20.0
        """
        # Always re-initialize the store context in case
        # :meth:`verify_certificate` is called multiple times.
        #
        # :meth:`_init` is called in :meth:`__init__` so _cleanup is called
        # before _init to ensure memory is not leaked.
        self._cleanup()
        self._init()
        ret = _lib.X509_verify_cert(self._store_ctx)
        if ret <= 0:
            self._cleanup()
            raise self._exception_from_context()

        # Note: X509_STORE_CTX_get1_chain returns a deep copy of the chain.
        cert_stack = _lib.X509_STORE_CTX_get1_chain(self._store_ctx)
        _openssl_assert(cert_stack != _ffi.NULL)

        result = []
        for i in range(_lib.sk_X509_num(cert_stack)):
            cert = _lib.sk_X509_value(cert_stack, i)
            _openssl_assert(cert != _ffi.NULL)
            pycert = X509._from_raw_x509_ptr(cert)
            result.append(pycert)

        # Free the stack but not the members which are freed by the X509 class.
        _lib.sk_X509_free(cert_stack)
        self._cleanup()
        return result


def load_certificate(type: int, buffer: bytes) -> X509:
    """
    Load a certificate (X509) from the string *buffer* encoded with the
    type *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)

    :param bytes buffer: The buffer the certificate is stored in

    :return: The X509 object
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    if type == FILETYPE_PEM:
        x509 = _lib.PEM_read_bio_X509(bio, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        x509 = _lib.d2i_X509_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if x509 == _ffi.NULL:
        _raise_current_error()

    return X509._from_raw_x509_ptr(x509)


def dump_certificate(type: int, cert: X509) -> bytes:
    """
    Dump the certificate *cert* into a buffer string encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1, or
        FILETYPE_TEXT)
    :param cert: The certificate to dump
    :return: The buffer with the dumped certificate in
    """
    bio = _new_mem_buf()

    if type == FILETYPE_PEM:
        result_code = _lib.PEM_write_bio_X509(bio, cert._x509)
    elif type == FILETYPE_ASN1:
        result_code = _lib.i2d_X509_bio(bio, cert._x509)
    elif type == FILETYPE_TEXT:
        result_code = _lib.X509_print_ex(bio, cert._x509, 0, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or " "FILETYPE_TEXT"
        )

    _openssl_assert(result_code == 1)
    return _bio_to_string(bio)


def dump_publickey(type: int, pkey: PKey) -> bytes:
    """
    Dump a public key to a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM` or
        :data:`FILETYPE_ASN1`).
    :param PKey pkey: The public key to dump
    :return: The buffer with the dumped key in it.
    :rtype: bytes
    """
    bio = _new_mem_buf()
    if type == FILETYPE_PEM:
        write_bio = _lib.PEM_write_bio_PUBKEY
    elif type == FILETYPE_ASN1:
        write_bio = _lib.i2d_PUBKEY_bio
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    result_code = write_bio(bio, pkey._pkey)
    if result_code != 1:  # pragma: no cover
        _raise_current_error()

    return _bio_to_string(bio)


def dump_privatekey(
    type: int,
    pkey: PKey,
    cipher: Optional[str] = None,
    passphrase: Optional[PassphraseCallableT] = None,
) -> bytes:
    """
    Dump the private key *pkey* into a buffer string encoded with the type
    *type*.  Optionally (if *type* is :const:`FILETYPE_PEM`) encrypting it
    using *cipher* and *passphrase*.

    :param type: The file type (one of :const:`FILETYPE_PEM`,
        :const:`FILETYPE_ASN1`, or :const:`FILETYPE_TEXT`)
    :param PKey pkey: The PKey to dump
    :param cipher: (optional) if encrypted PEM format, the cipher to use
    :param passphrase: (optional) if encrypted PEM format, this can be either
        the passphrase to use, or a callback for providing the passphrase.

    :return: The buffer with the dumped key in
    :rtype: bytes
    """
    bio = _new_mem_buf()

    if not isinstance(pkey, PKey):
        raise TypeError("pkey must be a PKey")

    if cipher is not None:
        if passphrase is None:
            raise TypeError(
                "if a value is given for cipher "
                "one must also be given for passphrase"
            )
        cipher_obj = _lib.EVP_get_cipherbyname(_byte_string(cipher))
        if cipher_obj == _ffi.NULL:
            raise ValueError("Invalid cipher name")
    else:
        cipher_obj = _ffi.NULL

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        result_code = _lib.PEM_write_bio_PrivateKey(
            bio,
            pkey._pkey,
            cipher_obj,
            _ffi.NULL,
            0,
            helper.callback,
            helper.callback_args,
        )
        helper.raise_if_problem()
    elif type == FILETYPE_ASN1:
        result_code = _lib.i2d_PrivateKey_bio(bio, pkey._pkey)
    elif type == FILETYPE_TEXT:
        if _lib.EVP_PKEY_id(pkey._pkey) != _lib.EVP_PKEY_RSA:
            raise TypeError("Only RSA keys are supported for FILETYPE_TEXT")

        rsa = _ffi.gc(_lib.EVP_PKEY_get1_RSA(pkey._pkey), _lib.RSA_free)
        result_code = _lib.RSA_print(bio, rsa, 0)
    else:
        raise ValueError(
            "type argument must be FILETYPE_PEM, FILETYPE_ASN1, or " "FILETYPE_TEXT"
        )

    _openssl_assert(result_code != 0)

    return _bio_to_string(bio)


class _PassphraseHelper:
    def __init__(
        self,
        type: int,
        passphrase: Optional[PassphraseCallableT],
        more_args: bool = False,
        truncate: bool = False,
    ) -> None:
        if type != FILETYPE_PEM and passphrase is not None:
            raise ValueError("only FILETYPE_PEM key format supports encryption")
        self._passphrase = passphrase
        self._more_args = more_args
        self._truncate = truncate
        self._problems: List[Exception] = []

    @property
    def callback(self) -> Any:
        if self._passphrase is None:
            return _ffi.NULL
        elif isinstance(self._passphrase, bytes) or callable(self._passphrase):
            return _ffi.callback("pem_password_cb", self._read_passphrase)
        else:
            raise TypeError("Last argument must be a byte string or a callable.")

    @property
    def callback_args(self) -> Any:
        if self._passphrase is None:
            return _ffi.NULL
        elif isinstance(self._passphrase, bytes) or callable(self._passphrase):
            return _ffi.NULL
        else:
            raise TypeError("Last argument must be a byte string or a callable.")

    def raise_if_problem(self, exceptionType: Type[Exception] = Error) -> None:
        if self._problems:
            # Flush the OpenSSL error queue
            try:
                _exception_from_error_queue(exceptionType)
            except exceptionType:
                pass

            raise self._problems.pop(0)

    def _read_passphrase(self, buf: Any, size: int, rwflag: Any, userdata: Any) -> int:
        try:
            if callable(self._passphrase):
                if self._more_args:
                    result = self._passphrase(size, rwflag, userdata)
                else:
                    result = self._passphrase(rwflag)
            else:
                assert self._passphrase is not None
                result = self._passphrase
            if not isinstance(result, bytes):
                raise ValueError("Bytes expected")
            if len(result) > size:
                if self._truncate:
                    result = result[:size]
                else:
                    raise ValueError("passphrase returned by callback is too long")
            for i in range(len(result)):
                buf[i] = result[i : i + 1]
            return len(result)
        except Exception as e:
            self._problems.append(e)
            return 0


def load_publickey(type: int, buffer: Union[str, bytes]) -> PKey:
    """
    Load a public key from a buffer.

    :param type: The file type (one of :data:`FILETYPE_PEM`,
        :data:`FILETYPE_ASN1`).
    :param buffer: The buffer the key is stored in.
    :type buffer: A Python string object, either unicode or bytestring.
    :return: The PKey object.
    :rtype: :class:`PKey`
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    if type == FILETYPE_PEM:
        evp_pkey = _lib.PEM_read_bio_PUBKEY(bio, _ffi.NULL, _ffi.NULL, _ffi.NULL)
    elif type == FILETYPE_ASN1:
        evp_pkey = _lib.d2i_PUBKEY_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if evp_pkey == _ffi.NULL:
        _raise_current_error()

    pkey = PKey.__new__(PKey)
    pkey._pkey = _ffi.gc(evp_pkey, _lib.EVP_PKEY_free)
    pkey._only_public = True
    return pkey


def load_privatekey(
    type: int,
    buffer: Union[str, bytes],
    passphrase: Optional[PassphraseCallableT] = None,
) -> PKey:
    """
    Load a private key (PKey) from the string *buffer* encoded with the type
    *type*.

    :param type: The file type (one of FILETYPE_PEM, FILETYPE_ASN1)
    :param buffer: The buffer the key is stored in
    :param passphrase: (optional) if encrypted PEM format, this can be
                       either the passphrase to use, or a callback for
                       providing the passphrase.

    :return: The PKey object
    """
    if isinstance(buffer, str):
        buffer = buffer.encode("ascii")

    bio = _new_mem_buf(buffer)

    helper = _PassphraseHelper(type, passphrase)
    if type == FILETYPE_PEM:
        evp_pkey = _lib.PEM_read_bio_PrivateKey(
            bio, _ffi.NULL, helper.callback, helper.callback_args
        )
        helper.raise_if_problem()
    elif type == FILETYPE_ASN1:
        evp_pkey = _lib.d2i_PrivateKey_bio(bio, _ffi.NULL)
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    if evp_pkey == _ffi.NULL:
        _raise_current_error()

    pkey = PKey.__new__(PKey)
    pkey._pkey = _ffi.gc(evp_pkey, _lib.EVP_PKEY_free)
    return pkey


def sign(pkey: PKey, data: Union[str, bytes], digest: str) -> bytes:
    """
    Sign a data string using the given key and message digest.

    :param pkey: PKey to sign with
    :param data: data to be signed
    :param digest: message digest to use
    :return: signature

    .. versionadded:: 0.11
    """
    data = _text_to_bytes_and_warn("data", data)

    digest_obj = _lib.EVP_get_digestbyname(_byte_string(digest))
    if digest_obj == _ffi.NULL:
        raise ValueError("No such digest method")

    md_ctx = _lib.EVP_MD_CTX_new()
    md_ctx = _ffi.gc(md_ctx, _lib.EVP_MD_CTX_free)

    _lib.EVP_SignInit(md_ctx, digest_obj)
    _lib.EVP_SignUpdate(md_ctx, data, len(data))

    length = _lib.EVP_PKEY_size(pkey._pkey)
    _openssl_assert(length > 0)
    signature_buffer = _ffi.new("unsigned char[]", length)
    signature_length = _ffi.new("unsigned int *")
    final_result = _lib.EVP_SignFinal(
        md_ctx, signature_buffer, signature_length, pkey._pkey
    )
    _openssl_assert(final_result == 1)

    return _ffi.buffer(signature_buffer, signature_length[0])[:]


def verify(cert: X509, signature: bytes, data: Union[str, bytes], digest: str) -> None:
    """
    Verify the signature for a data string.

    :param cert: signing certificate (X509 object) corresponding to the
        private key which generated the signature.
    :param signature: signature returned by sign function
    :param data: data to be verified
    :param digest: message digest to use
    :return: ``None`` if the signature is correct, raise exception otherwise.

    .. versionadded:: 0.11
    """
    data = _text_to_bytes_and_warn("data", data)

    digest_obj = _lib.EVP_get_digestbyname(_byte_string(digest))
    if digest_obj == _ffi.NULL:
        raise ValueError("No such digest method")

    pkey = _lib.X509_get_pubkey(cert._x509)
    _openssl_assert(pkey != _ffi.NULL)
    pkey = _ffi.gc(pkey, _lib.EVP_PKEY_free)

    md_ctx = _lib.EVP_MD_CTX_new()
    md_ctx = _ffi.gc(md_ctx, _lib.EVP_MD_CTX_free)

    _lib.EVP_VerifyInit(md_ctx, digest_obj)
    _lib.EVP_VerifyUpdate(md_ctx, data, len(data))
    verify_result = _lib.EVP_VerifyFinal(md_ctx, signature, len(signature), pkey)

    if verify_result != 1:
        _raise_current_error()
