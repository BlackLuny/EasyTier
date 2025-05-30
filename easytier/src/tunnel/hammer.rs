use std::net::SocketAddr;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use private_tun::snell_impl_ver::{
    config::get_password_from_string,
    encrypt::{EncryptReader, EncryptWriter},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::mpsc,
    task::JoinSet,
};

use super::TunnelInfo;
use crate::tunnel::common::setup_sokcet2;

use super::{
    check_scheme_and_get_socket_addr,
    common::{wait_for_connect_futures, FramedReader, FramedWriter, TunnelWrapper},
    IpVersion, Tunnel, TunnelError, TunnelListener,
};

const TCP_MTU_BYTES: usize = 2000;

const HELLO_REQ_MAGIC: u32 = 0x12345678;

const HELLO_RES_MAGIC: u32 = 0x98765432;

#[derive(Debug)]
pub struct HammerTunnelListener {
    addr: url::Url,
    key: [u8; 16],
    length_key: u32,
    accepted_streams_sender: mpsc::Sender<Box<dyn Tunnel>>,
    accepted_streams_receiver: mpsc::Receiver<Box<dyn Tunnel>>,
    listener_task: JoinSet<()>,
}

impl HammerTunnelListener {
    pub fn new(addr: url::Url, key: &str) -> Self {
        let (key, length_key) = get_password_from_string(key).unwrap();
        let (sender, receiver) = mpsc::channel(32);
        HammerTunnelListener {
            addr,
            key,
            length_key,
            accepted_streams_sender: sender,
            accepted_streams_receiver: receiver,
            listener_task: JoinSet::new(),
        }
    }
}

async fn do_handshake_as_server(
    stream: TcpStream,
    key: [u8; 16],
    length_key: u32,
    local_url: url::Url,
) -> Result<Box<dyn Tunnel>, std::io::Error> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in accept");
    }

    let info = TunnelInfo {
        tunnel_type: "hammer".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(
            super::build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "hammer").into(),
        ),
    };

    let (r, w) = stream.into_split();
    let mut encrypted_reader = EncryptReader::new(r, &key, length_key);
    let mut encrypted_writer = EncryptWriter::new(w, &key, length_key);

    let hello = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        encrypted_reader.read_u32().await
    })
    .await??;
    if hello != HELLO_REQ_MAGIC {
        encrypted_writer.shutdown().await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hello not match",
        ));
    } else {
        encrypted_writer.write_u32(HELLO_RES_MAGIC).await?;
    }

    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new(encrypted_reader, TCP_MTU_BYTES),
        FramedWriter::new(encrypted_writer),
        Some(info),
    )))
}

async fn do_handshake_as_client(
    stream: TcpStream,
    remote_url: url::Url,
    key: &[u8; 16],
    length_key: u32,
) -> Result<Box<dyn Tunnel>, std::io::Error> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in accept");
    }

    let info = TunnelInfo {
        tunnel_type: "hammer".to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "hammer").into(),
        ),
        remote_addr: Some(remote_url.into()),
    };

    let (r, w) = stream.into_split();
    let mut encrypted_reader = EncryptReader::new(r, &key, length_key);
    let mut encrypted_writer = EncryptWriter::new(w, &key, length_key);

    encrypted_writer.write_u32(HELLO_REQ_MAGIC).await?;
    encrypted_writer.flush().await?;
    let hello_res = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        encrypted_reader.read_u32().await
    })
    .await??;
    if hello_res != HELLO_RES_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hello not match",
        ));
    }

    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new(encrypted_reader, TCP_MTU_BYTES),
        FramedWriter::new(encrypted_writer),
        Some(info),
    )))
}
#[async_trait]
impl TunnelListener for HammerTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "hammer", IpVersion::Both)
                .await?;

        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        setup_sokcet2(&socket2_socket, &addr)?;
        let socket = TcpSocket::from_std_stream(socket2_socket.into());

        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!(?e, "set_nodelay fail in listen");
        }

        self.addr
            .set_port(Some(socket.local_addr()?.port()))
            .unwrap();
        let local_url = self.addr.clone();
        let key = self.key.clone();
        let length_key = self.length_key;
        let listener = socket.listen(1024)?;
        let accepted_streams_sender = self.accepted_streams_sender.clone();
        self.listener_task.spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let url = local_url.clone();
                    let key_clone = key.clone();
                    let length_key_clone = length_key;
                    let accepted_streams_sender_clone = accepted_streams_sender.clone();
                    tokio::spawn(async move {
                        let tun =
                            do_handshake_as_server(stream, key_clone, length_key_clone, url).await;
                        if let Ok(tun) = tun {
                            let _ = accepted_streams_sender_clone.send(tun).await;
                        }
                    });
                }
            }
        });
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        self.accepted_streams_receiver
            .recv()
            .await
            .ok_or(super::TunnelError::Anyhow(anyhow::anyhow!(
                "receiver closed"
            )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

fn get_tunnel_with_tcp_stream(
    stream: TcpStream,
    remote_url: url::Url,
    key: &[u8; 16],
    length_key: u32,
) -> Result<Box<dyn Tunnel>, super::TunnelError> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in get_tunnel_with_tcp_stream");
    }

    let info = TunnelInfo {
        tunnel_type: "hammer".to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "hammer").into(),
        ),
        remote_addr: Some(remote_url.into()),
    };

    let (r, w) = stream.into_split();
    let encrypted_reader = EncryptReader::new(r, key, length_key);
    let encrypted_writer = EncryptWriter::new(w, key, length_key);
    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new(encrypted_reader, TCP_MTU_BYTES),
        FramedWriter::new(encrypted_writer),
        Some(info),
    )))
}

#[derive(Debug)]
pub struct HammerTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    key: [u8; 16],
    length_key: u32,
}

impl HammerTunnelConnector {
    pub fn new(addr: url::Url, key: &str) -> Self {
        let (key, length_key) = get_password_from_string(key).unwrap();
        HammerTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            key,
            length_key,
        }
    }

    async fn connect_with_default_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(url = ?self.addr, ?addr, "connect tcp start, bind addrs: {:?}", self.bind_addrs);
        let stream = TcpStream::connect(addr).await?;
        tracing::info!(url = ?self.addr, ?addr, "connect tcp succ");
        return do_handshake_as_client(
            stream,
            self.addr.clone().into(),
            &self.key,
            self.length_key,
        )
        .await
        .map_err(|e| super::TunnelError::Anyhow(anyhow::anyhow!("handshake fail: {:?}", e)));
    }

    async fn connect_with_custom_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(bind_addr = ?bind_addr, ?addr, "bind addr");

            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            if let Err(e) = setup_sokcet2(&socket2_socket, bind_addr) {
                tracing::error!(bind_addr = ?bind_addr, ?addr, "bind addr fail: {:?}", e);
                continue;
            }

            let socket = TcpSocket::from_std_stream(socket2_socket.into());
            futures.push(socket.connect(addr.clone()));
        }
        if futures.is_empty() {
            tracing::warn!(?addr, "no bind addr, use default bind");
            return self.connect_with_default_bind(addr).await;
        }

        let ret = wait_for_connect_futures(futures).await;
        return do_handshake_as_client(ret?, self.addr.clone().into(), &self.key, self.length_key)
            .await
            .map_err(|e| super::TunnelError::Anyhow(anyhow::anyhow!("handshake fail: {:?}", e)));
    }
}

#[async_trait]
impl super::TunnelConnector for HammerTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "hammer", self.ip_version)
                .await?;
        if self.bind_addrs.is_empty() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{
        common::tests::{_tunnel_bench, _tunnel_pingpong},
        TunnelConnector,
    };

    use super::*;

    #[tokio::test]
    async fn tcp_pingpong() {
        let listener = HammerTunnelListener::new(
            "hammer://0.0.0.0:31011".parse().unwrap(),
            "1234567890123456",
        );
        let connector = HammerTunnelConnector::new(
            "hammer://127.0.0.1:31011".parse().unwrap(),
            "1234567890123456",
        );
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench() {
        let listener = HammerTunnelListener::new(
            "hammer://0.0.0.0:31012".parse().unwrap(),
            "1234567890123456",
        );
        let connector = HammerTunnelConnector::new(
            "hammer://127.0.0.1:31012".parse().unwrap(),
            "1234567890123456",
        );
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench_with_bind() {
        let listener = HammerTunnelListener::new(
            "hammer://127.0.0.1:11013".parse().unwrap(),
            "1234567890123456",
        );
        let mut connector = HammerTunnelConnector::new(
            "hammer://127.0.0.1:11013".parse().unwrap(),
            "1234567890123456",
        );
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn tcp_bench_with_bind_fail() {
        let listener = HammerTunnelListener::new(
            "hammer://127.0.0.1:11014".parse().unwrap(),
            "1234567890123456",
        );
        let mut connector = HammerTunnelConnector::new(
            "hammer://127.0.0.1:11014".parse().unwrap(),
            "1234567890123456",
        );
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn bind_same_port() {
        let mut listener =
            HammerTunnelListener::new("hammer://[::]:31014".parse().unwrap(), "1234567890123456");
        let mut listener2 = HammerTunnelListener::new(
            "hammer://0.0.0.0:31014".parse().unwrap(),
            "1234567890123456",
        );
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener =
            HammerTunnelListener::new("hammer://[::1]:31015".parse().unwrap(), "1234567890123456");
        let connector =
            HammerTunnelConnector::new("hammer://[::1]:31015".parse().unwrap(), "1234567890123456");
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener =
            HammerTunnelListener::new("hammer://[::1]:31015".parse().unwrap(), "1234567890123456");
        let mut connector =
            HammerTunnelConnector::new("hammer://[::1]:31015".parse().unwrap(), "1234567890123456");
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = HammerTunnelListener::new(
            "hammer://0.0.0.0:31015".parse().unwrap(),
            "1234567890123456",
        );
        let mut connector = HammerTunnelConnector::new(
            "hammer://0.0.0.0:31015".parse().unwrap(),
            "1234567890123456",
        );
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener =
            HammerTunnelListener::new("hammer://0.0.0.0:0".parse().unwrap(), "1234567890123456");
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener =
            HammerTunnelListener::new("hammer://[::]:0".parse().unwrap(), "1234567890123456");
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}
