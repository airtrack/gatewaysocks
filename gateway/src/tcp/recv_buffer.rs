use std::collections::BTreeMap;

use bytes::{Buf, Bytes};

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
struct Seq(u32);

impl PartialOrd for Seq {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Seq {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let diff = self.0.wrapping_sub(other.0) as i32;
        if diff < 0 {
            std::cmp::Ordering::Less
        } else if diff == 0 {
            std::cmp::Ordering::Equal
        } else {
            std::cmp::Ordering::Greater
        }
    }
}

/// TCP receive buffer that handles out-of-order data segments.
///
/// This buffer reassembles TCP segments that may arrive out of order due to
/// network conditions. It uses sequence numbers to properly order the data
/// and provides a contiguous stream of bytes to the application layer.
///
/// The buffer maintains an acknowledgment number that tracks the next expected
/// sequence number, and only allows reading of contiguous data before that point.
/// Out-of-order segments are stored until the gaps are filled.
#[derive(Default)]
pub(super) struct RecvBuffer {
    /// Ordered map of received data segments keyed by sequence number.
    /// BTreeMap is used to maintain segments in sequence order for efficient
    /// gap detection and contiguous data reading.
    recvd: BTreeMap<Seq, Bytes>,
    /// Current acknowledgment number - the next sequence number we expect.
    /// None until initialized with the initial sequence number.
    ack: Option<u32>,
}

impl RecvBuffer {
    /// Creates a new empty receive buffer.
    ///
    /// The buffer must be initialized with an acknowledgment number using
    /// [`initialize_ack`](Self::initialize_ack) before it can accept data.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Initializes the buffer with an acknowledgment number.
    ///
    /// This must be called before any data can be written to the buffer.
    /// The acknowledgment number represents the next sequence number expected.
    ///
    /// # Arguments
    ///
    /// * `ack` - The initial acknowledgment sequence number
    pub(super) fn initialize_ack(&mut self, ack: u32) {
        self.ack = Some(ack);
    }

    /// Writes data to the buffer at the specified sequence number.
    ///
    /// This function handles out-of-order data by storing it in the appropriate
    /// position based on sequence numbers. It automatically handles overlapping
    /// data and advances the acknowledgment number when contiguous data is available.
    ///
    /// # Arguments
    ///
    /// * `seq` - The sequence number where the data should be placed
    /// * `data` - The data bytes to write
    ///
    /// # Returns
    ///
    /// Returns the updated acknowledgment number on success, or an error if
    /// the buffer is not initialized.
    ///
    /// # Errors
    ///
    /// Returns an `InvalidInput` error if the buffer hasn't been initialized
    /// with an acknowledgment number.
    pub(super) fn write(&mut self, mut seq: u32, mut data: Bytes) -> std::io::Result<u32> {
        let ack = self.ack.ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ack is not initialized",
        ))?;

        if Seq(seq) < Seq(ack) {
            let len = ack.wrapping_sub(seq).min(data.len() as u32);
            data.advance(len as usize);
            seq = seq.wrapping_add(len);
        }

        let mut start = ack;
        while !data.is_empty() {
            (start, seq) = self.insert_slice(start, seq, &mut data);
        }

        let ack = self.advance_ack(ack);
        self.ack = Some(ack);
        Ok(ack)
    }

    /// Returns whether there is readable data available.
    ///
    /// Data is readable when there are contiguous bytes available before
    /// the current acknowledgment position.
    pub(super) fn readable(&self) -> bool {
        self.readable_size() > 0
    }

    /// Returns the number of bytes available for reading.
    ///
    /// Only contiguous data before the current acknowledgment position
    /// is considered readable. Out-of-order data that hasn't been connected
    /// to the readable stream is not included in this count.
    pub(super) fn readable_size(&self) -> usize {
        if self.ack.is_none() || self.recvd.is_empty() {
            return 0;
        }

        let ack = Seq(self.ack.unwrap());
        let (&k, _) = self.recvd.first_key_value().unwrap();
        if k < ack {
            ack.0.wrapping_sub(k.0) as usize
        } else {
            0
        }
    }

    /// Reads available data from the buffer into the provided buffer.
    ///
    /// Only reads contiguous data that is available for reading. The data
    /// is removed from the internal buffer after being read.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into
    ///
    /// # Returns
    ///
    /// The number of bytes actually read. This may be less than the buffer
    /// size if there isn't enough readable data available.
    pub(super) fn read(&mut self, buf: &mut [u8]) -> usize {
        if self.ack.is_none() {
            return 0;
        }

        let mut size = 0;
        let ack = Seq(self.ack.unwrap());

        while !self.recvd.is_empty() && !buf[size..].is_empty() {
            let (k, mut v) = self.recvd.pop_first().unwrap();
            if ack < k {
                self.recvd.insert(k, v);
                break;
            }

            let len = buf[size..].len().min(v.len());
            buf[size..size + len].copy_from_slice(&v[0..len]);

            v.advance(len);
            size += len;

            if !v.is_empty() {
                let k = Seq(k.0.wrapping_add(len as u32));
                self.recvd.insert(k, v);
            }
        }

        size
    }

    /// Inserts a slice of data into the buffer at the given sequence number.
    ///
    /// This function handles the complex logic of inserting data while avoiding
    /// duplicates and managing overlaps with existing data segments. It searches
    /// for the appropriate insertion point and handles three cases:
    /// 1. New data overlaps with existing data (skip overlapping portion)
    /// 2. New data fits between existing segments (insert as new segment)
    /// 3. New data exactly matches existing data (skip duplicate data)
    ///
    /// Returns the updated (start, seq) positions for continuing insertion.
    fn insert_slice(&mut self, mut start: u32, mut seq: u32, data: &mut Bytes) -> (u32, u32) {
        let mut iter = self.recvd.range(Seq(start)..);

        if let Some((&k, v)) = iter.next() {
            if k < Seq(seq) {
                // New data starts after an existing segment
                let k_end = Seq(k.0.wrapping_add(v.len() as u32));

                if Seq(seq) < k_end {
                    // New data overlaps with existing segment - skip overlap
                    let size = (k_end.0.wrapping_sub(seq) as usize).min(data.len());

                    data.advance(size);
                    seq = seq.wrapping_add(size as u32);
                    start = seq;
                } else {
                    // No overlap - continue from end of existing segment
                    start = k_end.0;
                }
            } else if k > Seq(seq) {
                // Gap exists - insert new data before existing segment
                let size = (k.0.wrapping_sub(seq) as usize).min(data.len());

                self.recvd.insert(Seq(seq), data.split_to(size));
                seq = seq.wrapping_add(size as u32);
                start = seq;
            } else {
                // New data starts at same position as existing - skip duplicate
                let size = v.len().min(data.len());

                data.advance(size);
                seq = seq.wrapping_add(size as u32);
                start = seq;
            }
        } else {
            // No more segments - insert remaining data
            self.recvd.insert(Seq(seq), data.split_to(data.len()));
        }

        (start, seq)
    }

    /// Advances the acknowledgment number as far as possible.
    ///
    /// This function scans through the received data segments starting from
    /// the current ACK position and advances the ACK number for each contiguous
    /// segment found. It stops when it encounters a gap in the sequence.
    ///
    /// This is used to determine how much contiguous data has been received
    /// and can be acknowledged to the sender.
    fn advance_ack(&mut self, mut ack: u32) -> u32 {
        let mut iter = self.recvd.range(Seq(ack)..);

        while let Some((k, v)) = iter.next() {
            if k.0 == ack {
                // Found contiguous segment - advance ACK by its length
                ack = ack.wrapping_add(v.len() as u32);
            } else {
                // Gap found - stop advancing
                break;
            }
        }

        ack
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_seq() {
        assert!(Seq(0) < Seq(1));
        assert!(Seq(u32::MAX) < Seq(0));
        assert!(Seq(u32::MAX) < Seq(1));
        assert!(Seq(u32::MAX) < Seq(20));
    }

    #[test]
    fn test_recv_buffer_normal() {
        let mut buffer = RecvBuffer::new();
        let mut ack = u32::MAX;
        buffer.initialize_ack(ack);

        buffer.write(1, Bytes::copy_from_slice(b"1")).unwrap();
        buffer.write(3, Bytes::copy_from_slice(b"34")).unwrap();
        buffer.write(6, Bytes::copy_from_slice(b"678")).unwrap();
        buffer
            .write(0, Bytes::copy_from_slice(b"0123456789"))
            .unwrap();
        ack = buffer.write(20, Bytes::copy_from_slice(b"20")).unwrap();

        assert_eq!(ack, u32::MAX);

        let mut buf = [0u8; 5];
        assert!(!buffer.readable());
        assert_eq!(buffer.read(&mut buf), 0);

        ack = buffer
            .write(u32::MAX, Bytes::copy_from_slice(b"u32::MAX"))
            .unwrap();
        assert_eq!(ack, 10);

        let mut iter = buffer.recvd.iter();
        assert_eq!(
            iter.next(),
            Some((&Seq(u32::MAX), &Bytes::copy_from_slice(b"u")))
        );
        assert_eq!(iter.next(), Some((&Seq(0), &Bytes::copy_from_slice(b"0"))));
        assert_eq!(iter.next(), Some((&Seq(1), &Bytes::copy_from_slice(b"1"))));
        assert_eq!(iter.next(), Some((&Seq(2), &Bytes::copy_from_slice(b"2"))));
        assert_eq!(iter.next(), Some((&Seq(3), &Bytes::copy_from_slice(b"34"))));
        assert_eq!(iter.next(), Some((&Seq(5), &Bytes::copy_from_slice(b"5"))));
        assert_eq!(
            iter.next(),
            Some((&Seq(6), &Bytes::copy_from_slice(b"678")))
        );
        assert_eq!(iter.next(), Some((&Seq(9), &Bytes::copy_from_slice(b"9"))));
        assert_eq!(
            iter.next(),
            Some((&Seq(20), &Bytes::copy_from_slice(b"20")))
        );
        assert_eq!(iter.next(), None);

        assert!(buffer.readable());
        assert_eq!(buffer.read(&mut buf), 5);
        assert_eq!(&buf[..5], b"u0123");

        assert!(buffer.readable());
        assert_eq!(buffer.read(&mut buf), 5);
        assert_eq!(&buf[..5], b"45678");

        assert!(buffer.readable());
        assert_eq!(buffer.read(&mut buf), 1);
        assert_eq!(&buf[..1], b"9");

        assert!(!buffer.readable());
        assert_eq!(buffer.read(&mut buf), 0);

        assert!(!buffer.readable());
        assert_eq!(buffer.read(&mut buf), 0);

        ack = buffer
            .write(6, Bytes::copy_from_slice(b"6789abcdef"))
            .unwrap();
        assert_eq!(ack, 16);

        iter = buffer.recvd.iter();
        assert!(buffer.readable());
        assert_eq!(
            iter.next(),
            Some((&Seq(10), &Bytes::copy_from_slice(b"abcdef")))
        );
        assert_eq!(
            iter.next(),
            Some((&Seq(20), &Bytes::copy_from_slice(b"20")))
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_recv_buffer_overlap() {
        let mut buffer = RecvBuffer::new();
        let mut ack = 0;
        buffer.initialize_ack(ack);

        ack = buffer.write(1, Bytes::copy_from_slice(b"123456")).unwrap();
        assert_eq!(ack, 0);

        ack = buffer.write(3, Bytes::copy_from_slice(b"3456789")).unwrap();
        assert_eq!(ack, 0);

        ack = buffer.write(0, Bytes::copy_from_slice(b"0")).unwrap();
        assert_eq!(ack, 10);

        let mut iter = buffer.recvd.iter();
        assert_eq!(iter.next(), Some((&Seq(0), &Bytes::copy_from_slice(b"0"))));
        assert_eq!(
            iter.next(),
            Some((&Seq(1), &Bytes::copy_from_slice(b"123456")))
        );
        assert_eq!(
            iter.next(),
            Some((&Seq(7), &Bytes::copy_from_slice(b"789")))
        );
        assert_eq!(iter.next(), None);

        let mut buf = [0u8; 10];
        assert_eq!(buffer.read(&mut buf), 10);
        assert_eq!(&buf[..], b"0123456789");
    }
}
