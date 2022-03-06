use super::SocksChannel;

pub struct UdpSocks5 {
    channel: SocksChannel,
}

impl UdpSocks5 {
    pub fn new(channel: SocksChannel) -> Self {
        Self { channel }
    }

    pub async fn run(&mut self) {
        loop {
            let _ = self.channel.rx.recv().await;
        }
    }
}
