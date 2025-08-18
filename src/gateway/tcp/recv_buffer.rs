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

    pub(super) fn write(&mut self, mut seq: u32, mut data: Bytes) {
        if let Some(ack) = self.ack {
            if Seq(seq) < Seq(ack) {
                let len = ack.wrapping_sub(seq).min(data.len() as u32);
                data.advance(len as usize);
                seq = seq.wrapping_add(len);
            }
        }

        while !data.is_empty() {
            self.insert_slice(&mut seq, &mut data);
        }
    }

    pub(super) fn advance_ack(&mut self, mut ack: u32) -> u32 {
        let mut iter = self.recvd.range(Seq(ack)..);

        while let Some((k, v)) = iter.next() {
            if k.0 == ack {
                ack = ack.wrapping_add(v.len() as u32);
            } else {
                break;
            }
        }

        self.ack = Some(ack);
        ack
    }

    pub(super) fn can_read(&self) -> bool {
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

    fn insert_slice(&mut self, seq: &mut u32, data: &mut Bytes) {
        let mut iter = self.recvd.range(Seq(*seq)..);

        if let Some((k, v)) = iter.next() {
            if k.0 == *seq {
                let size = v.len().min(data.len());
                data.advance(size);
                *seq = seq.wrapping_add(size as u32);
            } else {
                let size = (k.0.wrapping_sub(*seq) as usize).min(data.len());
                self.recvd.insert(Seq(*seq), data.split_to(size));
                *seq = seq.wrapping_add(size as u32);
            }
        } else {
            self.recvd.insert(Seq(*seq), data.split_to(data.len()));
        }
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
    fn test_recv_buffer() {
        let mut buffer = RecvBuffer::new();
        buffer.write(1, Bytes::copy_from_slice(b"1"));
        buffer.write(3, Bytes::copy_from_slice(b"34"));
        buffer.write(6, Bytes::copy_from_slice(b"678"));
        buffer.write(0, Bytes::copy_from_slice(b"0123456789"));
        buffer.write(20, Bytes::copy_from_slice(b"20"));

        let mut ack = buffer.advance_ack(u32::MAX);
        assert!(ack == u32::MAX);

        let mut buf = [0u8; 5];
        assert!(!buffer.can_read());
        assert!(buffer.read(&mut buf) == 0);

        buffer.write(u32::MAX, Bytes::copy_from_slice(b"u32::MAX"));
        ack = buffer.advance_ack(ack);
        assert!(ack == 10);

        let mut iter = buffer.recvd.iter();
        assert!(iter.next() == Some((&Seq(u32::MAX), &Bytes::copy_from_slice(b"u"))));
        assert!(iter.next() == Some((&Seq(0), &Bytes::copy_from_slice(b"0"))));
        assert!(iter.next() == Some((&Seq(1), &Bytes::copy_from_slice(b"1"))));
        assert!(iter.next() == Some((&Seq(2), &Bytes::copy_from_slice(b"2"))));
        assert!(iter.next() == Some((&Seq(3), &Bytes::copy_from_slice(b"34"))));
        assert!(iter.next() == Some((&Seq(5), &Bytes::copy_from_slice(b"5"))));
        assert!(iter.next() == Some((&Seq(6), &Bytes::copy_from_slice(b"678"))));
        assert!(iter.next() == Some((&Seq(9), &Bytes::copy_from_slice(b"9"))));
        assert!(iter.next() == Some((&Seq(20), &Bytes::copy_from_slice(b"20"))));
        assert!(iter.next() == None);

        assert!(buffer.can_read());
        assert!(buffer.read(&mut buf) == 5);
        assert!(&buf[..5] == b"u0123");

        assert!(buffer.can_read());
        assert!(buffer.read(&mut buf) == 5);
        assert!(&buf[..5] == b"45678");

        assert!(buffer.can_read());
        assert!(buffer.read(&mut buf) == 1);
        assert!(&buf[..1] == b"9");

        assert!(!buffer.can_read());
        assert!(buffer.read(&mut buf) == 0);

        assert!(!buffer.can_read());
        assert!(buffer.read(&mut buf) == 0);

        buffer.write(6, Bytes::copy_from_slice(b"6789abcdef"));
        ack = buffer.advance_ack(ack);
        assert!(ack == 16);

        iter = buffer.recvd.iter();
        assert!(buffer.can_read());
        assert!(iter.next() == Some((&Seq(10), &Bytes::copy_from_slice(b"abcdef"))));
        assert!(iter.next() == Some((&Seq(20), &Bytes::copy_from_slice(b"20"))));
        assert!(iter.next() == None);
    }
}
