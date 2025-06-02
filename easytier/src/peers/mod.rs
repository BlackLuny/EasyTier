mod graph_algo;

pub mod peer;
// pub mod peer_conn;
pub mod peer_conn;
pub mod peer_conn_ping;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_rpc_service;
pub mod route_trait;
pub mod rpc_service;

pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;

pub mod peer_task;

#[cfg(test)]
pub mod tests;

use crate::tunnel::packet_def::ZCPacket;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(&self, _zc_packet: ZCPacket) -> Option<ZCPacket> {
        Some(_zc_packet)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool;

    fn id(&self) -> String {
        format!("{:p}", self)
    }
}

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

// pub type PacketRecvChan = tachyonix::Sender<ZCPacket>;
// pub type PacketRecvChanReceiver = tachyonix::Receiver<ZCPacket>;
// pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
//     tachyonix::channel(128)
// }
pub type PacketRecvChan = tokio::sync::mpsc::Sender<ZCPacket>;
pub type PacketRecvChanReceiver = tokio::sync::mpsc::Receiver<ZCPacket>;
pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
    tokio::sync::mpsc::channel(128)
}
pub async fn recv_packet_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<ZCPacket, anyhow::Error> {
    packet_recv_chan_receiver
        .recv()
        .await
        .ok_or(anyhow::anyhow!("recv_packet_from_chan failed"))
}

#[derive(Clone)]
pub enum PacketRecvChainPair {
    Single(PacketRecvChan),
    Double(PacketRecvChan, PacketRecvChan),
}

impl PacketRecvChainPair {
    pub fn new(
        data_packet_recv_chan: PacketRecvChan,
        ctl_packet_recv_chan: Option<PacketRecvChan>,
    ) -> Self {
        if let Some(ctl_packet_recv_chan) = ctl_packet_recv_chan {
            Self::Double(data_packet_recv_chan, ctl_packet_recv_chan)
        } else {
            Self::Single(data_packet_recv_chan)
        }
    }
    pub fn get_data_packet_recv_chan(&self) -> &PacketRecvChan {
        match self {
            Self::Single(data_packet_recv_chan) => data_packet_recv_chan,
            Self::Double(data_packet_recv_chan, _) => data_packet_recv_chan,
        }
    }
    pub fn get_ctl_packet_recv_chan(&self) -> &PacketRecvChan {
        match self {
            Self::Single(r) => r,
            Self::Double(_, ctl_packet_recv_chan) => ctl_packet_recv_chan,
        }
    }
}
