use std::{fmt::Display, net::SocketAddrV4};

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum State {
    Listen = 0,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl State {
    pub(super) fn from_integer(value: usize) -> Option<Self> {
        match value {
            0 => Some(State::Listen),
            1 => Some(State::SynRcvd),
            2 => Some(State::Estab),
            3 => Some(State::FinWait1),
            4 => Some(State::FinWait2),
            5 => Some(State::Closing),
            6 => Some(State::TimeWait),
            7 => Some(State::CloseWait),
            8 => Some(State::LastAck),
            9 => Some(State::Closed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AddrPair(pub SocketAddrV4, pub SocketAddrV4);

impl Display for AddrPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("({}, {})", self.0, self.1))
    }
}
