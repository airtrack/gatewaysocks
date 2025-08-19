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

#[derive(Default)]
pub(super) struct RecvBuffer {
    recvd: BTreeMap<Seq, Bytes>,
    ack: Option<u32>,
}

impl RecvBuffer {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn initialize_ack(&mut self, ack: u32) {
        self.ack = Some(ack);
    }

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

    pub(super) fn readable(&self) -> bool {
        if self.ack.is_none() || self.recvd.is_empty() {
            return false;
        }

        let ack = Seq(self.ack.unwrap());
        let (&k, _) = self.recvd.first_key_value().unwrap();
        k < ack
    }

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

    fn insert_slice(&mut self, mut start: u32, mut seq: u32, data: &mut Bytes) -> (u32, u32) {
        let mut iter = self.recvd.range(Seq(start)..);

        if let Some((&k, v)) = iter.next() {
            if k < Seq(seq) {
                let k_end = Seq(k.0.wrapping_add(v.len() as u32));

                if Seq(seq) < k_end {
                    let size = (k_end.0.wrapping_sub(seq) as usize).min(data.len());

                    data.advance(size);
                    seq = seq.wrapping_add(size as u32);
                    start = seq;
                } else {
                    start = k_end.0;
                }
            } else if k > Seq(seq) {
                let size = (k.0.wrapping_sub(seq) as usize).min(data.len());

                self.recvd.insert(Seq(seq), data.split_to(size));
                seq = seq.wrapping_add(size as u32);
                start = seq;
            } else {
                let size = v.len().min(data.len());

                data.advance(size);
                seq = seq.wrapping_add(size as u32);
                start = seq;
            }
        } else {
            self.recvd.insert(Seq(seq), data.split_to(data.len()));
        }

        (start, seq)
    }

    fn advance_ack(&mut self, mut ack: u32) -> u32 {
        let mut iter = self.recvd.range(Seq(ack)..);

        while let Some((k, v)) = iter.next() {
            if k.0 == ack {
                ack = ack.wrapping_add(v.len() as u32);
            } else {
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
