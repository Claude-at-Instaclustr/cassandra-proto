use std::borrow::BorrowMut;
use std::cell::{RefCell, RefMut};
use std::io::{Cursor, Read};

use super::*;
use crate::compression::Compressor;
use crate::frame::frame_error::{AdditionalErrorInfo, CDRSError, SimpleError};
use crate::error;
use crate::frame::frame_response::ResponseBody;
use crate::frame::FromCursor;
use crate::types::data_serialization_types::decode_timeuuid;
use crate::types::CString;
use crate::types::{from_bytes, from_u16_bytes, CStringList, UUID_LEN};


/// Create a protocol error message
fn make_protocol_error(msg: &str) -> CDRSError {
    CDRSError {
        error_code: 0x000A, // protocol error
        message: CString::new(msg.to_string()),
        additional_info: AdditionalErrorInfo::Protocol(SimpleError {}),
    }
}

/// Create a server error message
fn make_server_error(msg: &str) -> CDRSError {
    CDRSError {
        error_code: 0x0000, // server error
        message: CString::new(msg.to_string()),
        additional_info: AdditionalErrorInfo::Protocol(SimpleError {}),
    }
}

pub fn parse_raw_frame<E>(
    cursor_cell: & RefCell<dyn Read>,
    compressor: & dyn Compressor<CompressorError = E>,
) -> Result<Frame, CDRSError>
where
    E: std::error::Error,
{
    let mut version_bytes = [0; Version::BYTE_LENGTH];
    let mut flag_bytes = [0; Flag::BYTE_LENGTH];
    let mut opcode_bytes = [0; Opcode::BYTE_LENGTH];
    let mut stream_bytes = [0; STREAM_LEN];
    let mut length_bytes = [0; LENGTH_LEN];
    let mut cursor = cursor_cell.borrow_mut();

    // NOTE: order of reads matters
    // check the version before we progress
    let mut y = cursor.read_exact(&mut version_bytes);
    let version = if y.is_ok()  {
        let v = Version::from(version_bytes.to_vec());
        match v {
            Version::Other(_c) => {
                // do not change error string, it is part of the defined protocol
                return Err(make_protocol_error(
                    "Invalid or unsupported protocol version",
                ))
            },
            _ => v,
        }
    } else {
        return Err(make_server_error(&y.unwrap_err().to_string()));
    };
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


    let flags = Flag::get_collection(flag_bytes[0]);
    let stream = from_u16_bytes(&stream_bytes);
    let opcode = Opcode::from(opcode_bytes[0]);
    let length = from_bytes(&length_bytes) as usize;

    // FIXME:
    //   Once a new feature to safely pass an uninitialized buffer to `Read` becomes available,
    //   we no longer need to zero-initialize `body_bytes` before passing to `Read`.
    let frame = if length > 0 {

        let mut body_bytes = vec![0 as u8; length];
        let y = cursor.read_exact(&mut body_bytes);
        if y.is_err() {
            return Err(make_server_error(&y.unwrap_err().to_string()));
        }

            let full_body = extract_body_bytes(body_bytes, compressor, &flags)?;

            // read the body


            // Use cursor to get tracing id, warnings and actual body
        let mut body_cursor = Cursor::new(full_body.as_slice());

            Frame {
                version: version,
                opcode: opcode,
                stream: stream,
                tracing_id: if flags.iter().any(|flag| flag == &Flag::Tracing) {
                    extract_tracing_id(&mut body_cursor)?
                } else {
                    None
                },
                warnings: if flags.iter().any(|flag| flag == &Flag::Warning) {
                    extract_warnings(&mut body_cursor)?
                } else {
                    vec![]
                },
                body: extract_body(&mut body_cursor)?,
                flags: flags,
            }

    } else {
        Frame {
            version: version,
            opcode: opcode,
            stream: stream,
            body: vec![],
            tracing_id: if flags.iter().any(|flag| flag == &Flag::Tracing) {
                return Err(make_protocol_error(
                    "Tracing flag set, no tracing ID provided",
                ))
            } else {
                None
            },
            warnings: vec![],
            flags: flags,
        }
    };
    Ok(frame)
}

/// Reads the body from a Cursor.
///
/// Length of body is determined by `frame_header.length`.
///
/// # Arguments
/// * `cursor` - The cursor to read the body from.
/// * `length` - The expected length of the body.
/// * `compressor` - The compressor implementation to decompress the body with.
///
/// # Returns
/// * The body of the frame.
/// * CDRSError - Server Error (0x0000) if the entire body can not be read or if the compressor
/// fails.
///
fn extract_body_bytes<E>( body_bytes : Vec<u8>,
              compressor: &dyn Compressor<CompressorError = E>,
            flags : &Vec<Flag>) -> Result<Vec<u8>,CDRSError>
    where
        E: std::error::Error,
{
    let full_body = if flags.iter().any(|flag| flag == &Flag::Compression) {
        compressor
            .decode(body_bytes)
            .map_err(|err| make_server_error(&*format!("{} while uncompressing body", err.to_string())))?
    } else {
        body_bytes
    };

    Ok(full_body)

}

/// Extracts the tracing ID from the current cursor position if the `frame_header.flags` contains
/// the Tracing flag.
///
/// If the flag is not set, returns `None` otherwise returns the UUID that is the tracing ID.
/// # Arguments
/// * `cursor` - The cursor to read the tracing id from.
///
fn extract_tracing_id(
    cursor: &mut Cursor<&[u8]>,
) -> Result<Option<uuid::Uuid>, CDRSError> {
    let mut tracing_bytes = [0 as u8; UUID_LEN];
    let x = cursor.read_exact(&mut tracing_bytes)
        .map_err(|x| make_server_error(&*format!("{} while reading tracing id", x.to_string())));
    if x.is_err() {
        Err(x.unwrap_err())
    } else {
        decode_timeuuid(&tracing_bytes)
            .map(|x| Some(x))
            .map_err(|x| make_server_error(&x.to_string()))
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
    cursor: &mut Cursor<&[u8]>,
) -> Result<Vec<String>, CDRSError> {
        CStringList::from_cursor(cursor)
            .map_err(|x| make_server_error(&*format!("{} while extracting warnings", x.to_string())))
            .map(|x| x.into_plain())
}

/// Extracts the body from a cursor.
fn extract_body(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, CDRSError> {
    let mut body = vec![];
    let x = cursor
        .read_to_end(&mut body)
        .map_err(|x| make_server_error(&*format!("{} while extracting body", x.to_string())));
    if x.is_err() {
        Err(x.unwrap_err())
    } else {
        Ok(body)
    }
}

pub fn parse_frame<E>(
    cursor_cell: &RefCell<dyn Read>,
    compressor: &dyn Compressor<CompressorError = E>,
) -> error::Result<Frame>
    where
        E: std::error::Error,
{
    let result = parse_raw_frame( cursor_cell, compressor );
    if result.is_ok() {
        let frame = result.unwrap();
        match frame.opcode {
            Opcode::Error => frame.get_body().and_then(|err| match err {
                ResponseBody::Error(err) => Err(error::Error::Server(err)),
                _ => unreachable!(),
            }),
            _ => Ok(frame),
        }
    } else {
        Err(error::Error::Server(result.unwrap_err()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::traits::AsByte;
    use bytes::{BytesMut, BufMut, Buf};
    use crate::compressors::no_compression::NoCompression;
    use uuid::Uuid;

    #[test]
    #[cfg(not(feature = "v3"))]
    fn test_frame_version_as_byte() {
        let request_version = Version::Request;
        assert_eq!(request_version.as_byte(), 0x04);
        let response_version = Version::Response;
        assert_eq!(response_version.as_byte(), 0x84);
    }

    #[test]
    fn test_read_header_invalid_version() {
        let mut buf = vec![0 as u8;64];
        let compressor = NoCompression::new();
        buf[0]=0x42;

        let cursor = Cursor::new( buf );
            let refcell = RefCell::new(cursor);
            let r = parse_raw_frame(&refcell, &compressor);
            assert_eq!(r.is_err(), true);
            let err = r.unwrap_err();
            assert_eq!(err.error_code, 0x000A); // protocol error
            assert_eq!(err.message.as_str(), "Invalid or unsupported protocol version");

    }

    #[test]
    fn test_read_header_no_header() {
        let buf = vec![0 as u8;0];
        let compressor = NoCompression::new();

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);
        let r = parse_raw_frame(&refcell, &compressor);
        assert_eq!( r.is_ok(), false );
        let err  = r.unwrap_err();
        assert_eq!( err.error_code, 0 ); // server error
        assert_eq!( err.message.as_str(), "failed to fill whole buffer");
        assert!( match err.additional_info {
            AdditionalErrorInfo::Protocol(_x) => true,
            _ => false,
        });
    }

    #[test]
    fn test_read_body() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( 0x0 ); // flags (Tracing)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( Opcode::Options.as_byte() ); // opcode (Option)
        buf.put_u32( 11 ); // length

        // put in the body
        buf.put( "Hello World".as_bytes());

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);

        let r = parse_raw_frame(&refcell, &compressor);
        assert_eq!( r.is_ok(), true );
        let frame = r.unwrap() ;
        assert_eq!( frame.version, Version::Request );
        assert!( frame.flags.is_empty());
        assert!( frame.tracing_id.is_none());
        assert!( frame.warnings.is_empty() );
        assert_eq!( frame.stream, 0x0102 );
        assert_eq!( frame.opcode, Opcode::Options );
        //assert_eq!( frame.length, 11 );
        assert_eq!( frame.body.as_slice(), "Hello World".as_bytes());
    }

    #[test]
    fn test_read_short_body() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( 0x0 ); // flags
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 15 ); // length

        // put in the body
        buf.put( "Hello World".as_bytes());

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);
        let r = parse_raw_frame(& refcell, &compressor);
        assert!( r.is_err() );
        let err = r.unwrap_err();
        assert_eq!( err.error_code, 0x0000 ); // server error
        assert_eq!( err.message.as_str(), "failed to fill whole buffer" );
        assert!( match err.additional_info {
            AdditionalErrorInfo::Protocol(_x) => true,
            _ => false,
        });
    }

    #[test]
    fn test_read_long_body() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( 0x0); // flags
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 11 ); // length

        // put in the body
        buf.put( "Hello WorldNow is the time".as_bytes());

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);
        let r = parse_raw_frame(& refcell, &compressor);
        assert!( r.is_ok() );
        let frame = r.unwrap();
        assert_eq!( frame.body.as_slice(), "Hello World".as_bytes());
        assert!( frame.tracing_id.is_none());
        assert!( frame.warnings.is_empty() );
    }

    #[test]
    fn test_extract_tracing_id() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( Flag::Tracing.as_byte() ); // flags (Tracing)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 19 ); // length


        let uuid  = Uuid::new_v4();
        for i in uuid.as_bytes() {
            buf.put_u8(*i);
        }
        // put in the body
        buf.put( "Hello World".as_bytes());

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);
        let r = parse_raw_frame(& refcell, &compressor);
        assert!( r.is_ok() );
        let frame = r.unwrap();
        assert_eq!( frame.flags.iter().any(|flag| flag == &Flag::Tracing), true);
        assert_eq!( frame.tracing_id.unwrap(), uuid );
        assert!( frame.warnings.is_empty() );
    }

    /// test tracing flag set but no body provided.
    #[test]
    fn test_extract_tracing_id_no_data() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( Flag::Tracing.as_byte() ); // flags (Tracing)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 0 ); // length

        let cursor = Cursor::new( buf );
        let refcell = RefCell::new(cursor);
        let r = parse_raw_frame(& refcell, &compressor);
        assert!( r.is_err() );
        let err = r.unwrap_err();
        assert_eq!( err.error_code, 0x000A ); // protocol error
        assert_eq!( err.message.as_str(), "Tracing flag set, no tracing ID provided" );
    }
/*
    #[test]
    fn test_extract_warnings() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( Flag::Warning.as_byte() ); // flags (Warning)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 2+11+2+16+13 ); // length (see segments below)

        // string list comprising 2 strings
        buf.put_u16( 2 );
        // put in hello world
        buf.put_u16( 11);
        buf.put( "Hello World".as_bytes());
        // put in "now is the time.."
        buf.put_u16( 16 );
        buf.put( "Now is the time.".as_bytes());

        // put in the body (13 bytes)
        buf.put( "What is this?".as_bytes());

        let mut refcell = RefCell::new(buf.chunk());
        let r = parse_raw_frame(&mut refcell, &compressor);
        assert_eq!( r.is_ok(), true );
        let opt = r.unwrap() ;
        assert_eq!(opt.is_some(), true ); // no header read
        let header = opt.unwrap();
        assert_eq( frame.flags.iter().any(|flag| flag == &Flag::Warning), true);
        assert_eq!( header.length, 2+11+2+16+13 );
        let b = read_body(&header, &compressor, &mut buf );
        let v = b.unwrap();
        let mut cursor = Cursor::new(v.as_slice());
        let r = extract_warnings( &header, &mut cursor);
        assert_eq!( r.is_ok(), true );
        let warnings = r.unwrap();
        assert_eq!( warnings[0], "Hello World");
        assert_eq!( warnings[1], "Now is the time.");
    }

    #[test]
    fn test_extract_warnings_no_flag() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( 0x0 ); // flags
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 2+11+2+16+13 ); // length (see segments below)

        // string list comprising 2 strings
        buf.put_u16( 2 );
        // put in hello world
        buf.put_u16( 11);
        buf.put( "Hello World".as_bytes());
        // put in "now is the time.."
        buf.put_u16( 16 );
        buf.put( "Now is the time.".as_bytes());

        // put in the body (13 bytes)
        buf.put( "What is this?".as_bytes());

        let mut refcell = RefCell::new(buf.chunk());
        let r = parse_raw_frame(&mut refcell, &compressor);
        assert_eq!( r.is_ok(), true );
        let opt = r.unwrap() ;
        assert_eq!(opt.is_some(), true ); // no header read
        let header = opt.unwrap();
        assert_eq!( header.flags, 0x0 );
        assert_eq!( header.length, 2+11+2+16+13 );
        let b = read_body(&header, &compressor, &mut buf );
        let v = b.unwrap();
        let mut cursor = Cursor::new(v.as_slice());
        let r = extract_warnings( &header, &mut cursor);
        assert_eq!( r.is_ok(), true );
        let warnings = r.unwrap();
        assert_eq!( warnings.len(), 0);
    }

    #[test]
    fn test_extract_warnings_no_data() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( Flag::Warning.as_byte() ); // flags (Warnings)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        buf.put_u32( 0 ); // length

        let mut refcell = RefCell::new(buf.chunk());
        let r = parse_raw_frame(&mut refcell, &compressor);
        assert_eq!( r.is_ok(), true );
        let opt = r.unwrap() ;
        assert_eq!(opt.is_some(), true ); // no header read
        let header = opt.unwrap();
        assert_eq( frame.flags.iter().any(|flag| flag == &Flag::Warning), true);
        assert_eq!( header.length, 0 );
        let b = read_body(&header, &compressor, &mut buf );
        let v = b.unwrap();
        let mut cursor = Cursor::new(v.as_slice());
        let r = extract_warnings( &header, &mut cursor);
        assert_eq!( r.is_err(), true );
        let err = r.unwrap_err();
        assert_eq!( err.error_code, 0x0000 ); // server error
        assert_eq!( err.message.as_str(), "IO error: failed to fill whole buffer while extracting warnings" );
    }

    /*
    pub fn parse_frame<E>(
    mut src: &mut BytesMut,
    compressor: &dyn Compressor<CompressorError = E>,
    frame_header_original: Option<FrameHeader>,
) -> Result<(Option<Frame>, Option<FrameHeader>), CDRSError>
     */

    #[test]
    fn test_parse_frame() {
        let mut buf = BytesMut::with_capacity(64);
        let compressor = NoCompression::new();

        // put in the header
        /*
      +---------+---------+---------+---------+---------+
      | version |  flags  |      stream       | opcode  |
      +---------+---------+---------+---------+---------+
      |                length                 |
      +---------+---------+---------+---------+
         */
        buf.put_u8(0x4); // version
        buf.put_u8( Flag::Tracing.as_byte() | Flag::Warning.as_byte() ); // flags (Tracing & Warnings)
        buf.put_u16( 0x0102 ); //stream
        buf.put_u8( 0x05 ); // opcode (Option)
        let len = 16+2+2+11+2+16+13;
        buf.put_u32( len ); // length (see segments below)

        let uuid  = Uuid::new_v4(); // 16 bytes
        for i in uuid.as_bytes() {
            buf.put_u8(*i);
        }

        // string list comprising 2 strings
        buf.put_u16( 2 );   // 2 bytes
        // put in hello world
        buf.put_u16( 11);   // 2 bytes
        buf.put( "Hello World".as_bytes()); // 11 bytes
        // put in "now is the time.."
        buf.put_u16( 16 );   // 2 bytes
        buf.put( "Now is the time.".as_bytes()); // 16 bytes

        // put in the body (13 bytes)
        buf.put( "What is this?".as_bytes());  // 13 bytes


        let mut refcell = RefCell::new(buf.chunk());
        let r = parse_raw_frame(&mut refcell, &compressor);
        assert_eq!( r.is_ok(), true );
        let (frame_opt, header_opt) = r.unwrap() ;
        assert_eq!(frame_opt.is_some(), true );
        assert_eq!(header_opt.is_none(), true );
        let frame = frame_opt.unwrap();
        assert_eq!( frame.flags.contains( &Flag::Tracing), true );
        assert_eq!( frame.flags.contains( &Flag::Warning), true );
        assert_eq!( frame.stream, 0x0102);
        assert_eq!( frame.opcode, Opcode::Options);
        assert_eq!( frame.tracing_id.is_some(), true);
        assert_eq!( frame.tracing_id.unwrap(), uuid );
        assert_eq!( frame.warnings.len(), 2 );
        assert_eq!( frame.warnings[0], "Hello World" );
        assert_eq!( frame.warnings[1], "Now is the time." );
        assert_eq!( frame.body, "What is this?".as_bytes());
    }
*/
}
