use std::{fmt::Display, net::SocketAddrV4};

#[derive(PartialEq, Eq, Copy, Clone)]
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
        f.write_str(self.to_str())
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

    pub fn to_str(&self) -> &'static str {
        match self {
            State::Listen => "Listen",
            State::SynRcvd => "SynRcvd",
            State::Estab => "Estab",
            State::FinWait1 => "FinWait1",
            State::FinWait2 => "FinWait2",
            State::Closing => "Closing",
            State::TimeWait => "TimeWait",
            State::CloseWait => "CloseWait",
            State::LastAck => "LastAck",
            State::Closed => "Closed",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AddrPair {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
}

impl Display for AddrPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("({}, {})", self.source, self.destination))
    }
}
