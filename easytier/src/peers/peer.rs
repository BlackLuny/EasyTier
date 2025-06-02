use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;

use tokio::{select, sync::mpsc, task::JoinHandle};

use tracing::Instrument;

use super::peer_conn::{PeerConn, PeerConnId};
use crate::common::timed_cache::Timed;
use crate::tunnel::TunnelError;
use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        PeerId,
    },
    tunnel::packet_def::ZCPacket,
};
use crate::{peers::PacketRecvChainPair, proto::cli::PeerConnInfo};

type ArcPeerConn = Arc<PeerConn>;
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    global_ctx: ArcGlobalCtx,

    packet_recv_chain_pair: PacketRecvChainPair,

    close_event_sender: mpsc::Sender<PeerConnId>,
    close_event_listener: JoinHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn: std::sync::RwLock<Option<Timed<ArcPeerConn>>>,
}

impl Peer {
    pub fn new(
        peer_node_id: PeerId,
        packet_recv_chain_pair: PacketRecvChainPair,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::new());
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());

        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let global_ctx_copy = global_ctx.clone();
        let close_event_listener = tokio::spawn(
            async move {
                loop {
                    select! {
                        ret = close_event_receiver.recv() => {
                            if ret.is_none() {
                                break;
                            }
                            let ret = ret.unwrap();
                            tracing::warn!(
                                ?peer_node_id,
                                ?ret,
                                "notified that peer conn is closed",
                            );

                            if let Some((_, conn)) = conns_copy.remove(&ret) {
                                global_ctx_copy.issue_event(GlobalCtxEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
                            }
                        }

                        _ = shutdown_notifier_copy.notified() => {
                            close_event_receiver.close();
                            tracing::warn!(?peer_node_id, "peer close event listener notified");
                        }
                    }
                }
                tracing::info!("peer {} close event listener exit", peer_node_id);
            }
            .instrument(tracing::info_span!(
                "peer_close_event_listener",
                ?peer_node_id,
            )),
        );

        Peer {
            peer_node_id,
            conns: conns.clone(),
            packet_recv_chain_pair,
            global_ctx,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn: std::sync::RwLock::new(None),
        }
    }

    pub async fn add_peer_conn(&self, mut conn: PeerConn) {
        let close_event_sender = self.close_event_sender.clone();
        let close_notifier = conn.get_close_notifier();
        tokio::spawn(async move {
            let conn_id = close_notifier.get_conn_id();
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            if let Err(e) = close_event_sender.send(conn_id).await {
                tracing::warn!(?conn_id, "failed to send close event: {}", e);
            }
        });

        conn.start_recv_loop(self.packet_recv_chain_pair.clone())
            .await;
        conn.start_pingpong();

        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerConnAdded(conn.get_conn_info()));
        self.conns.insert(conn.get_conn_id(), Arc::new(conn));
    }

    fn select_conn(&self) -> Option<ArcPeerConn> {
        {
            let guard = self.default_conn.read().unwrap();
            if let Some(conn) = &*guard {
                if !conn.is_expired(std::time::Duration::from_secs(5)) {
                    return Some(conn.get().clone());
                }
            }
        }

        // find a conn with the smallest latency
        let mut min_latency = std::u64::MAX;
        let mut min_conn = None;
        for conn in self.conns.iter() {
            let latency = conn.value().get_latency_us();
            if latency < min_latency {
                min_latency = latency;
                min_conn = Some(conn.clone());
            }
        }
        if let Some(conn) = min_conn {
            *self.default_conn.write().unwrap() = Some(Timed::new(conn.clone()));
            return Some(conn);
        }
        None
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        if let Err(e) = self.try_send_msg_internal(msg) {
            let msg = match e {
                Error::TunnelError(TunnelError::BufferFull(e)) => e,
                Error::TunnelError(TunnelError::ChannelClosed(e)) => e,
                _ => return Err(e),
            };
            let Some(conn) = self.select_conn() else {
                return Err(Error::PeerNoConnectionError(self.peer_node_id));
            };
            conn.send_msg(msg).await?;
        }
        Ok(())
    }

    pub fn try_send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        self.try_send_msg_internal(msg)
    }

    fn try_send_msg_internal(&self, msg: ZCPacket) -> Result<(), Error> {
        let Some(conn) = self.select_conn() else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        let e = match conn.try_send_msg(msg) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) => e,
        };
        if self.conns.len() == 1 {
            return Err(Error::TunnelError(e));
        }
        let mut msg = match e {
            TunnelError::BufferFull(e) => e,
            TunnelError::ChannelClosed(e) => e,
            _ => return Err(Error::TunnelError(e)),
        };
        // try other conn
        // find a conn with the smallest latency
        let mut all_conns = self
            .conns
            .iter()
            .map(|conn| conn.clone())
            .collect::<Vec<_>>();
        all_conns.sort_by_key(|conn| conn.get_latency_us());

        for conn in all_conns {
            match conn.try_send_msg(msg) {
                Ok(()) => {
                    *self.default_conn.write().unwrap() = Some(Timed::new(conn));
                    return Ok(());
                }
                Err(e) => {
                    msg = match e {
                        TunnelError::BufferFull(e) => e,
                        TunnelError::ChannelClosed(e) => e,
                        _ => return Err(Error::TunnelError(e)),
                    };
                }
            }
        }
        Err(Error::TunnelError(TunnelError::BufferFull(msg)))
    }

    pub async fn close_peer_conn(&self, conn_id: &PeerConnId) -> Result<(), Error> {
        let has_key = self.conns.contains_key(conn_id);
        if !has_key {
            return Err(Error::NotFound);
        }
        self.close_event_sender.send(conn_id.clone()).await.unwrap();
        Ok(())
    }

    pub fn list_peer_conns(&self) -> Vec<PeerConnInfo> {
        let mut ret = vec![];
        for conn in self.conns.iter() {
            // do not lock here, otherwise it will cause dashmap deadlock
            ret.push(conn.get_conn_info());
        }
        ret
    }

    pub fn get_default_conn(&self) -> Option<ArcPeerConn> {
        let guard = self.default_conn.read().unwrap();
        guard.as_ref().map(|conn| conn.get().clone())
    }
}

// pritn on drop
impl Drop for Peer {
    fn drop(&mut self) {
        self.shutdown_notifier.notify_one();
        tracing::info!("peer {} drop", self.peer_node_id);
    }
}

#[cfg(test)]
mod tests {

    use tokio::time::timeout;

    use crate::{
        common::{global_ctx::tests::get_mock_global_ctx, new_peer_id},
        peers::{create_packet_recv_chan, peer_conn::PeerConn, PacketRecvChainPair},
        tunnel::ring::create_ring_tunnel_pair,
    };

    use super::Peer;

    #[tokio::test]
    async fn close_peer() {
        let (local_packet_send, _local_packet_recv) = create_packet_recv_chan();
        let (remote_packet_send, _remote_packet_recv) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx();
        let local_peer = Peer::new(
            new_peer_id(),
            PacketRecvChainPair::new(local_packet_send, None),
            global_ctx.clone(),
        );
        let remote_peer = Peer::new(
            new_peer_id(),
            PacketRecvChainPair::new(remote_packet_send, None),
            global_ctx.clone(),
        );

        let (local_tunnel, remote_tunnel) = create_ring_tunnel_pair();
        let mut local_peer_conn =
            PeerConn::new(local_peer.peer_node_id, global_ctx.clone(), local_tunnel);
        let mut remote_peer_conn =
            PeerConn::new(remote_peer.peer_node_id, global_ctx.clone(), remote_tunnel);

        assert!(!local_peer_conn.handshake_done());
        assert!(!remote_peer_conn.handshake_done());

        let (a, b) = tokio::join!(
            local_peer_conn.do_handshake_as_client(),
            remote_peer_conn.do_handshake_as_server()
        );
        a.unwrap();
        b.unwrap();

        let local_conn_id = local_peer_conn.get_conn_id();

        local_peer.add_peer_conn(local_peer_conn).await;
        remote_peer.add_peer_conn(remote_peer_conn).await;

        assert_eq!(local_peer.list_peer_conns().len(), 1);
        assert_eq!(remote_peer.list_peer_conns().len(), 1);

        let close_handler =
            tokio::spawn(async move { local_peer.close_peer_conn(&local_conn_id).await });

        // wait for remote peer conn close
        timeout(std::time::Duration::from_secs(5), async {
            while (&remote_peer).list_peer_conns().len() != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        println!("wait for close handler");
        close_handler.await.unwrap().unwrap();
    }
}
