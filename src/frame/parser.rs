use super::*;
use crate::compression::Compressor;
use crate::error;
use crate::frame::frame_error::{AdditionalErrorInfo, CDRSError, SimpleError};
use crate::frame::frame_response::ResponseBody;
use crate::frame::FromCursor;
use crate::types::data_serialization_types::decode_timeuuid;
use crate::types::CString;
use crate::types::{from_bytes, from_u16_bytes, CStringList, UUID_LEN};
use bytes::BytesMut;
use std::io::{Cursor, Read};
use uuid;

#[derive(Debug, Clone)]
pub struct FrameHeader {
    version: Version,
    flags: u8, //Vec<Flag>,
    stream: u16,
    opcode: Opcode,
    length: usize,
}

fn make_protocol_error(msg: &str) -> CDRSError {
    CDRSError {
        error_code: 0x000A, // protocol error
        message: CString::new(msg.to_string()),
        additional_info: AdditionalErrorInfo::Protocol(SimpleError {}),
    }
}

fn make_server_error(msg: &str) -> CDRSError {
    CDRSError {
        error_code: 0x0000, // server error
        message: CString::new(msg.to_string()),
        additional_info: AdditionalErrorInfo::Protocol(SimpleError {}),
    }
}

/// Reads the header from the input stream.
/// If there is not enough data in the buffer will return None.
///
fn read_header(src: &mut BytesMut) -> Result<Option<FrameHeader>, CDRSError> {
    let head_len = 9;
    let max_frame_len = 1024 * 1024 * 15; //15MB

    // Make sure we have some data
    if src.len() == 0 {
        return Ok(None);
    }
    // we have at least one byte so read the version.  We read the version byte first so that
    // we can handle versions that have a different header size properly by reporting them as
    // invalid or unsupported.
    let version: Version = match src.first() {
        Some(x) => {
            let v = Version::from(*x);
            match v {
                Version::Other(_c) => {
                    return Err(make_protocol_error(
                        "Invalid or unsupported protocol version",
                    ))
                }
                _ => v,
            }
        }
        // no first byte -- should not happen as we already checked buffer length
        None => return Err(make_server_error("Can not read protocol version")),
    };

    // make sure we have enough data to read the header.
    if src.len() < head_len {
        return Ok(None);
    }

    let mut version_bytes = [0; Version::BYTE_LENGTH];
    let mut flag_bytes = [0; Flag::BYTE_LENGTH];
    let mut opcode_bytes = [0; Opcode::BYTE_LENGTH];
    let mut stream_bytes = [0; STREAM_LEN];
    let mut length_bytes = [0; LENGTH_LEN];
    let head_buf = src.split_to(head_len);
    let mut cursor = Cursor::new(head_buf);

    // NOTE: order of reads matters
    // We handle the error at the end of this block.
    let mut y = cursor.read_exact(&mut version_bytes);
    if y.is_ok() {
        y = cursor.read_exact(&mut flag_bytes);
    }
    if y.is_ok() {
        y = cursor.read_exact(&mut stream_bytes);
    }
    if y.is_ok() {
        y = cursor.read_exact(&mut opcode_bytes);
    }
    if y.is_ok() {
        y = cursor.read_exact(&mut length_bytes);
    }
    if y.is_err() {
        return Err(make_server_error(&y.unwrap_err().to_string()));
    }

    // check for error length problem.
    let header_length = from_bytes(&length_bytes) as usize;
    if header_length > max_frame_len {
        return Err(make_protocol_error("Max frame length exceeded"));
    }

    Ok(Some(FrameHeader {
        version,
        flags: flag_bytes[0],
        stream: from_u16_bytes(&stream_bytes),
        opcode: Opcode::from(opcode_bytes[0]),
        length: header_length,
    }))
}

/// Parses the input bytes into a Cassandra frame.
/// //
/// This function may be called repeatedly.  The initial call should pass None as the argument for
/// the `frame_header_original` argument.  On subsequent calls the FrameHeader returned from the
/// previous call should be passed.
///
/// # Returns
/// * (None,None) if there is not enough data to read the header
/// * (None,FrameHeader) if there is enough data for the header but not enough for the body.
/// * (Frame,None) when the entire frame has been read.
/// * CDRSError
///   * Protocol Error (0x000A) when the version does not match or the max frame length is exceeded
///   * Server Error (0x0000) if the buffers can not be read or other internal errors.
///
/// # Arguments
/// * `src` - The input byte stream to read.
/// * `compressor` - The compression implementation for compressed data.
/// * `frame_header_original - The frame header extracted in an earlier attempt to construct this
/// frame.
pub fn parse_frame<E>(
    mut src: &mut BytesMut,
    compressor: &dyn Compressor<CompressorError = E>,
    frame_header_original: Option<FrameHeader>,
) -> Result<(Option<Frame>, Option<FrameHeader>), CDRSError>
where
    E: std::error::Error,
{
    let head_len = 9;

    // If the frame_header_original is set then we are trying to parse the data
    // and have already extracted the header.

    let frame_header: FrameHeader = match frame_header_original {
        Some(x) => x,
        None => {
            let r = read_header(src);
            if r.is_err() {
                return r.map(|_y| (None, None));
            } else {
                match r.ok() {
                    Some(x) => x.unwrap(),
                    None => return Ok((None, None)),
                }
            }
        }
    };

    // check that there buffer contains all the bytes for the body.
    if src.len() < frame_header.length {
        // make sure there is space for the body
        src.reserve(frame_header.length - src.len());
        return Ok((None, Some(frame_header)));
    }
    let full_body = read_body(&frame_header, compressor, &mut src)?;

    let mut body_cursor = Cursor::new(full_body.as_slice());

    let frame = Frame {
        version: frame_header.version,
        flags: Flag::get_collection(frame_header.flags),
        stream: frame_header.stream,
        opcode: frame_header.opcode,
        tracing_id: extract_tracing_id(&frame_header, &mut body_cursor)?,
        warnings: extract_warnings(&frame_header, &mut body_cursor)?,
        body: extract_body(&mut body_cursor)?,
    };

    src.reserve(head_len);
    Ok((Some(frame), None))
}

/// Reads the body from a Cursor.  
///
/// Length of body is determined by `frame_header.length`.
///
/// # Arguments
/// * `frame_header` - The header for the frame being parsed.
/// * `compressor` - The compressor implementation to decompress the body with.
/// * `cursor` - The cursor to read the body from.
///
/// # Returns
/// * The body of the frame.
/// * CDRSError - Server Error (0x0000) if the entire body can not be read or if the compressor
/// fails.
///
fn read_body<E>(
    frame_header: &FrameHeader,
    compressor: &dyn Compressor<CompressorError = E>,
    src: &mut BytesMut,
) -> Result<Vec<u8>, CDRSError>
where
    E: std::error::Error,
{
    let mut cursor = Cursor::new(src.split_to(frame_header.length));
    let mut body_bytes = Vec::with_capacity(frame_header.length);
    unsafe {
        body_bytes.set_len(frame_header.length);
    }

    let y = cursor
        .read_exact(&mut body_bytes)
        .map_err(|x| make_server_error(&x.to_string()));
    if y.is_err() {
        Err(y.unwrap_err())
    } else {
        Ok(if Flag::has_compression(frame_header.flags) {
            compressor
                .decode(body_bytes)
                .map_err(|x| make_server_error(&x.to_string()))?
        } else {
            body_bytes
        })
    }
}

/// Extracts the tracing ID from the current cursor position if the `frame_header.flags` contains
/// the Tracing flag.
///
/// If the flag is not set, returns `None` otherwise returns the UUID that is the tracing ID.
/// # Arguments
/// * `frame_header` - The header for the frame being parsed.
/// * `cursor` - The cursor to read the tracing id from.
///
fn extract_tracing_id(
    frame_header: &FrameHeader,
    cursor: &mut Cursor<&[u8]>,
) -> Result<Option<uuid::Uuid>, CDRSError> {
    // Use cursor to get tracing id, warnings and actual body

    if Flag::has_tracing(frame_header.flags) {
        let mut tracing_bytes = [0 as u8; UUID_LEN];

        let x = cursor
            .read_exact(&mut tracing_bytes)
            .map_err(|x| make_server_error(&x.to_string()));

        if x.is_err() {
            Err(x.unwrap_err())
        } else {
            decode_timeuuid(&tracing_bytes)
                .map(|x| Some(x))
                .map_err(|x| make_server_error(&x.to_string()))
        }
    } else {
        Ok(None)
    }
}

/// Extracts the warnings from the current cursor position if the `frame_header.flags` contains
/// the Warning flag.
///
/// If the flag is not set, returns an empty Vec otherwise returns the Vec of warning messages.
/// # Arguments
/// * `frame_header` - The header for the frame being parsed.
/// * `cursor` - The cursor to read the warnings from.
///
fn extract_warnings(
    frame_header: &FrameHeader,
    cursor: &mut Cursor<&[u8]>,
) -> Result<Vec<String>, CDRSError> {
    if Flag::has_warning(frame_header.flags) {
        CStringList::from_cursor(cursor)
            .map_err(|x| make_server_error(&x.to_string()))
            .map(|x| x.into_plain())
    } else {
        Ok(vec![])
    }
}

/// Extracts the body from a cursor.
fn extract_body(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CDRSError> {
    let mut body = vec![];
    let x = cursor
        .read_to_end(&mut body)
        .map_err(|x| make_server_error(&x.to_string()));
    if x.is_err() {
        Err(x.unwrap_err())
    } else {
        Ok(body)
    }
}

fn convert_frame_into_result(frame: Frame) -> error::Result<(Option<Frame>, Option<FrameHeader>)> {
    match frame.opcode {
        Opcode::Error => frame.get_body().and_then(|err| match err {
            ResponseBody::Error(err) => Err(error::Error::Server(err)),
            _ => unreachable!(),
        }),
        _ => Ok((Some(frame), None)),
    }
}
