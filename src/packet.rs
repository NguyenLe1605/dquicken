use core::ops::RangeBounds;

#[allow(non_camel_case_types)]
pub enum FrameType {
    PADDING,
    PING,
    ACK(u8),
    RESET_STREAM,
    STOP_SENDING,
    CRYPTO,
    NEW_TOKEN,
    STREAM(u8),
    MAX_DATA,
    MAX_STREAM_DATA,
    MAX_STREAMS(u8),
    DATA_BLOCKED,
    STREAM_DATA_BLOCKED,
    STREAMS_BLOCKED(u8),
    NEW_CONNECTION_ID,
    RETIRE_CONNECTION_ID,
    PATH_CHALLENGE,
    PATH_RESPONSE,
    CONNECTION_CLOSE(u8),
    HANDSHAKE_DONE,
    UNKNOWN(u8),
}

impl FrameType {
    pub fn from_u8(num: u8) -> Self {
        match num {
            0x00 => Self::PADDING,
            0x01 => Self::PING,
            num if (0x02..=0x03).contains(&num) => Self::ACK(num),
            0x04 => Self::RESET_STREAM,
            0x05 => Self::STOP_SENDING,
            0x06 => Self::CRYPTO,
            0x07 => Self::NEW_TOKEN,
            num if (0x08..=0x0f).contains(&num) => Self::STREAM(num),
            0x10 => Self::MAX_DATA,
            0x11 => Self::MAX_STREAM_DATA,
            num if (0x12..=0x13).contains(&num) => Self::MAX_STREAMS(num),
            0x14 => Self::DATA_BLOCKED,
            0x15 => Self::STREAM_DATA_BLOCKED,
            num if (0x16..=0x17).contains(&num) => Self::STREAMS_BLOCKED(num),
            0x18 => Self::NEW_CONNECTION_ID,
            0x19 => Self::RETIRE_CONNECTION_ID,
            0x1a => Self::PATH_CHALLENGE,
            0x1b => Self::PATH_RESPONSE,
            num if (0x1c..=0x1d).contains(&num) => Self::CONNECTION_CLOSE(num),
            0x1e => Self::HANDSHAKE_DONE,
            num => Self::UNKNOWN(num),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::PADDING => 0x00,
            Self::PING => 0x01,
            Self::ACK(n) => *n,
            Self::RESET_STREAM => 0x04,
            Self::STOP_SENDING => 0x05,
            Self::CRYPTO => 0x06,
            Self::NEW_TOKEN => 0x07,
            Self::STREAM(num) => *num,
            Self::MAX_DATA => 0x10,
            Self::MAX_STREAM_DATA => 0x11,
            Self::MAX_STREAMS(num) => *num,
            Self::DATA_BLOCKED => 0x14,
            Self::STREAM_DATA_BLOCKED => 0x15,
            Self::STREAMS_BLOCKED(num) => *num,
            Self::NEW_CONNECTION_ID => 0x18,
            Self::RETIRE_CONNECTION_ID => 0x19,
            Self::PATH_CHALLENGE => 0x1a,
            Self::PATH_RESPONSE => 0x1b,
            Self::CONNECTION_CLOSE(num) => *num,
            Self::HANDSHAKE_DONE => 0x1e,
            Self::UNKNOWN(num) => *num,
        }
    }
}

pub struct Frame {
    pub ftype: FrameType,
    pub fields: Vec<u8>,
}

#[derive(Debug)]
#[repr(u8)]
pub enum LongPacketType {
    Inital = 0x0,
    ZeroRTT,
    Handshake,
    Retry,
    Unknown(u8),
}

impl From<u8> for LongPacketType {
    fn from(value: u8) -> Self {
        match value {
            0x0 => Self::Inital,
            0x1 => Self::ZeroRTT,
            0x2 => Self::Handshake,
            0x3 => Self::Retry,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug)]
pub struct LongHeader<'a> {
    /// Fixed Bit: The next bit (0x40) of byte 0 is set to 1, unless the packet
    /// is a Version Negotiation packet. Packets containing a zero value for this
    /// bit are not valid packets in this version and MUST be discarded. A value
    /// of 1 for this bit allows QUIC to coexist with other protocols; see [RFC7983].
    pub fixed_bit: bool,

    /// Long Packet Type: The next two bits (those with a mask of 0x30) of byte 0
    /// contain a packet type. Packet types are listed in Table 5.
    pub ptype: LongPacketType,

    /// Type-Specific Bits: The semantics of the lower four bits (those with a mask
    /// of 0x0f) of byte 0 are determined by the packet type.
    pub reserved_bits: u8,

    /// Packet Number Length: In packet types that contain a Packet Number field, the
    /// least significant two bits (those with a mask of 0x03) of byte 0 contain the
    /// length of the Packet Number field, encoded as an unsigned two-bit integer that
    /// is one less than the length of the Packet Number field in bytes. That is, the
    /// length of the Packet Number field is the value of this field plus one. These
    /// bits are protected using header protection; see Section 5.4 of [QUIC-TLS].
    pub packet_number_length: u8,

    /// Version: The QUIC Version is a 32-bit field that follows the first byte.
    /// This field indicates the version of QUIC that is in use and determines
    /// how the rest of the protocol fields are interpreted.
    pub version: u32,

    /// Destination Connection ID Length: The byte following the version contains
    /// the length in bytes of the Destination Connection ID field that follows it.
    /// This length is encoded as an 8-bit unsigned integer. In QUIC version 1,
    /// this value MUST NOT exceed 20 bytes. Endpoints that receive a version 1
    /// long header with a value larger than 20 MUST drop the packet. In order to
    /// properly form a Version Negotiation packet, servers SHOULD be able to read
    /// longer connection IDs from other QUIC versions.
    pub destination_connection_id_length: u8,

    /// Destination Connection ID:  The Destination Connection ID field follows
    /// the Destination Connection ID Length field, which indicates the length
    /// of this field. Section 7.2 describes the use of this field in more detail.
    pub destination_connection_id: &'a [u8],

    /// Source Connection ID Length: The byte following the Destination Connection
    /// ID contains the length in bytes of the Source Connection ID field that
    /// follows it. This length is encoded as an 8-bit unsigned integer. In QUIC
    /// version 1, this value MUST NOT exceed 20 bytes. Endpoints that receive a
    /// version 1 long header with a value larger than 20 MUST drop the packet.
    /// In order to properly form a Version Negotiation packet, servers SHOULD
    /// be able to read longer connection IDs from other QUIC versions.
    pub source_connection_id_length: u8,

    /// Source Connection ID: The Source Connection ID field follows the Source
    /// Connection ID Length field, which indicates the length of this field.
    /// Section 7.2 describes the use of this field in more detail.
    pub source_connection_id: &'a [u8],

    // Length of the header, may delete later
    pub len: usize,
}

impl<'a> LongHeader<'a> {
    pub fn from_slice(buf: &'a [u8]) -> Self {
        let mut pos = 0;
        let first = buf[pos];
        println!("{:x}", first);
        pos += 1;
        let header_form = first & 0x80;
        if header_form == 0x0 {
            todo!("Short header");
        }

        let version = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        if version == 0 {
            todo!("Version negotiation packet");
        }
        pos += 4;
        let dcid_len = buf[pos];
        pos += 1;
        let dcid = &buf[pos..pos + dcid_len as usize];
        pos += dcid_len as usize;

        let scid_len = buf[pos];
        pos += 1;
        let scid = &buf[pos..pos + scid_len as usize];
        pos += scid_len as usize;

        let fixed_bit = (first & 0x40) == 0x40;
        let reserved_bits = first & 0x0c;
        let packet_number_length = (first & 0x03) + 1;
        let ptype = LongPacketType::from(first & 0x30);

        Self {
            fixed_bit,
            ptype,
            reserved_bits,
            packet_number_length,
            version,
            destination_connection_id_length: dcid_len,
            destination_connection_id: dcid,
            source_connection_id_length: scid_len,
            source_connection_id: scid,
            len: pos,
        }
    }
}

#[derive(Debug)]
pub struct ShortHeader {
    /// Fixed Bit: The next bit (0x40) of byte 0 is set to 1. Packets containing
    /// a zero value for this bit are not valid packets in this version and MUST
    /// be discarded. A value of 1 for this bit allows QUIC to coexist with
    /// other protocols; see [RFC7983].
    pub fixed_bit: bool,

    /// Spin Bit: The third most significant bit (0x20) of byte 0 is the
    /// latency spin bit, set as described in Section 17.4.
    pub spin_bit: bool,

    /// Reserved Bits: The next two bits (those with a mask of 0x18) of byte 0
    /// are reserved. These bits are protected using header protection;
    /// see Section 5.4 of [QUIC-TLS]. The value included prior to protection MUST
    /// be set to 0. An endpoint MUST treat receipt of a packet that has a non-zero
    /// value for these bits, after removing both packet and header protection,
    /// as a connection error of type PROTOCOL_VIOLATION. Discarding such a packet
    /// after only removing header protection can expose the endpoint to attacks;
    /// see Section 9.5 of [QUIC-TLS].
    pub reserved_bit: [bool; 2],

    /// Key Phase: The next bit (0x04) of byte 0 indicates the key phase,
    /// which allows a recipient of a packet to identify the packet protection
    /// keys that are used to protect the packet. See [QUIC-TLS] for details.
    /// This bit is protected using header protection; see Section 5.4 of [QUIC-TLS].
    pub key_phase: bool,

    /// Packet Number Length: The least significant two bits (those with a mask of 0x03)
    /// of byte 0 contain the length of the Packet Number field, encoded as
    /// an unsigned two-bit integer that is one less than the length of the
    /// Packet Number field in bytes. That is, the length of the Packet Number
    /// field is the value of this field plus one. These bits are protected
    /// using header protection; see Section 5.4 of [QUIC-TLS].
    pub packet_number_length: u8,

    /// Destination Connection ID: The Destination Connection ID is a connection
    /// ID that is chosen by the intended recipient of the packet.
    /// See Section 5.1 for more details.
    pub destination_connection_id: [u8; 160],
    // length of the header, may remove later
}

#[derive(Debug)]
pub enum Packet<'a> {
    Inital {
        header: LongHeader<'a>,

        /// Token Length: A variable-length integer specifying the length of
        /// the Token field, in bytes. This value is 0 if no token is present.
        /// Initial packets sent by the server MUST set the Token Length field to 0;
        /// clients that receive an Initial packet with a non-zero Token Length
        /// field MUST either discard the packet or generate a connection error
        /// of type PROTOCOL_VIOLATION.
        token_length: usize,

        /// Token: The value of the token that was previously provided in a
        /// Retry packet or NEW_TOKEN frame; see Section 8.1.
        token: Vec<u8>,
    },
    VersionNegotiaion {
        header: LongHeader<'a>,
        supported_version: u32,
    },
    ZeroRTT {
        header: LongHeader<'a>,
        length: usize,
        packet_number: u32,
        packet_payload: Vec<u8>,
    },
    Handshake {
        header: LongHeader<'a>,
        length: usize,
        packet_number: u32,
        packet_payload: Vec<u8>,
    },
    Retry {
        header: LongHeader<'a>,

        /// Retry Token: An opaque token that the server can use to validate
        /// the client's address.
        retry_token: Vec<u8>,

        /// Retry Integrity Tag: Defined in Section 5.8 ("Retry Packet Integrity")
        /// of [QUIC-TLS].
        retry_integrity_tag: [u8; 16],
    },
    OneRTT {
        header: ShortHeader,

        /// Packet Number: The Packet Number field is 1 to 4 bytes long. The packet
        /// number is protected using header protection; see Section 5.4 of [QUIC-TLS].
        /// The length of the Packet Number field is encoded in Packet Number
        /// Length field.
        /// See Section 17.1 for details.
        packet_number: u32,

        /// Packet Payload: 1-RTT packets always include a 1-RTT protected payload.
        packet_payload: Vec<u8>,
    },
}

impl<'a> Packet<'a> {
    pub fn from_slice(buf: &'a [u8]) -> Self {
        let _ = buf;
        unimplemented!()
    }
}
