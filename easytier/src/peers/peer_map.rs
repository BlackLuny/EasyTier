use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Context;
use dashmap::DashMap;
use tokio::sync::RwLock;

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        timed_cache::Timed,
        PeerId,
    },
    peers::PacketRecvChainPair,
    proto::{cli::PeerConnInfo, common::PeerFeatureFlag},
    tunnel::{packet_def::ZCPacket, TunnelError},
};

use super::{
    peer::Peer,
    peer_conn::{PeerConn, PeerConnId},
    route_trait::{ArcRoute, NextHopPolicy},
    PacketRecvChan,
};

struct CacheInfo {
    route_cache: DashMap<(PeerId, NextHopPolicy), Timed<PeerId>>,
}

pub struct PeerMap {
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_map: DashMap<PeerId, Arc<Peer>>,
    packet_send: PacketRecvChainPair,
    routes: RwLock<Vec<ArcRoute>>,
    alive_conns: Arc<DashMap<(PeerId, PeerConnId), PeerConnInfo>>,
    cache_info: CacheInfo,
}

impl PeerMap {
    pub fn new(
        data_packet_send: PacketRecvChan,
        ctl_packet_send: Option<PacketRecvChan>,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
    ) -> Self {
        let packet_send = PacketRecvChainPair::new(data_packet_send, ctl_packet_send);
        PeerMap {
            global_ctx,
            my_peer_id,
            peer_map: DashMap::new(),
            packet_send,
            routes: RwLock::new(Vec::new()),
            alive_conns: Arc::new(DashMap::new()),
            cache_info: CacheInfo {
                route_cache: DashMap::new(),
            },
        }
    }

    async fn add_new_peer(&self, peer: Peer) {
        let peer_id = peer.peer_node_id.clone();
        self.peer_map.insert(peer_id.clone(), Arc::new(peer));
        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerAdded(peer_id));
    }

    pub async fn add_new_peer_conn(&self, peer_conn: PeerConn) {
        self.maintain_alive_conns(&peer_conn);
        let peer_id = peer_conn.get_peer_id();
        let no_entry = self.peer_map.get(&peer_id).is_none();
        if no_entry {
            let new_peer = Peer::new(peer_id, self.packet_send.clone(), self.global_ctx.clone());
            new_peer.add_peer_conn(peer_conn).await;
            self.add_new_peer(new_peer).await;
        } else {
            let peer = self.peer_map.get(&peer_id).unwrap().clone();
            peer.add_peer_conn(peer_conn).await;
        }
    }

    fn maintain_alive_conns(&self, peer_conn: &PeerConn) {
        let close_notifier = peer_conn.get_close_notifier();
        let alive_conns_weak = Arc::downgrade(&self.alive_conns);
        let conn_id = close_notifier.get_conn_id();
        let peer_id = peer_conn.get_peer_id();
        self.alive_conns
            .insert((peer_id, conn_id.clone()), peer_conn.get_conn_info());
        tokio::spawn(async move {
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            let mut alive_conn_count = 0;
            if let Some(alive_conns) = alive_conns_weak.upgrade() {
                alive_conns.remove(&(peer_id, conn_id)).unwrap();
                alive_conn_count = alive_conns.len();
            }
            tracing::debug!(
                ?conn_id,
                "peer conn is closed, current alive conns: {}",
                alive_conn_count
            );
        });
    }

    fn get_peer_by_id(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.peer_map.get(&peer_id).map(|v| v.clone())
    }

    pub fn has_peer(&self, peer_id: PeerId) -> bool {
        peer_id == self.my_peer_id || self.peer_map.contains_key(&peer_id)
    }

    pub async fn send_msg_directly(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        allow_drop_packet: bool,
    ) -> Result<(), Error> {
        if dst_peer_id == self.my_peer_id {
            let packet_send = self.packet_send.clone();
            // TODO: use data or ctl packet send chan?
            tokio::spawn(async move {
                let ret = packet_send
                    .get_data_packet_recv_chan()
                    .send(msg)
                    .await
                    .with_context(|| "send msg to self failed");
                if ret.is_err() {
                    tracing::error!("send msg to self failed: {:?}", ret);
                }
            });
            return Ok(());
        }

        match self.get_peer_by_id(dst_peer_id) {
            Some(peer) => {
                if allow_drop_packet {
                    if let Err(e) = peer.try_send_msg(msg) {
                        tracing::error!("send msg to peer failed: {:?} drop it", e);
                    }
                } else {
                    peer.send_msg(msg).await?;
                }
            }
            None => {
                tracing::error!("no peer for dst_peer_id: {}", dst_peer_id);
                return Err(Error::RouteError(Some(format!(
                    "peer map sengmsg directly no connected dst_peer_id: {}",
                    dst_peer_id
                ))));
            }
        }

        Ok(())
    }

    pub fn get_latency_to_peer(&self, peer_id: PeerId) -> Option<u64> {
        let Some(peer) = self.get_peer_by_id(peer_id) else {
            return None;
        };
        peer.get_default_conn().map(|conn| conn.get_latency_us())
    }

    pub async fn get_gateway_peer_id(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Option<PeerId> {
        if dst_peer_id == self.my_peer_id {
            return Some(dst_peer_id);
        }
        let has_direct_conn = self.has_peer(dst_peer_id);
        if matches!(policy, NextHopPolicy::LeastHop) && has_direct_conn {
            return Some(dst_peer_id);
        }

        if let Some(Some(dst_peer_id)) = self
            .cache_info
            .route_cache
            .get(&(dst_peer_id, policy.clone()))
            .map(|x| {
                if !x.is_expired(Duration::from_secs(10)) {
                    Some(x.get().clone())
                } else {
                    None
                }
            })
        {
            return Some(dst_peer_id);
        }

        // get route info
        for route in self.routes.read().await.iter() {
            if let Some(gateway_peer_id) = route
                .get_next_hop_with_policy(dst_peer_id, policy.clone())
                .await
            {
                if matches!(policy, NextHopPolicy::LeastCost)
                    && has_direct_conn
                    && gateway_peer_id != dst_peer_id
                    && self.has_peer(gateway_peer_id)
                {
                    // compare latency and select direct conn if latency is abs diff less than 10% of max latency
                    let latency_to_dst = self.get_latency_to_peer(dst_peer_id);
                    let latency_to_gateway = self.get_latency_to_peer(gateway_peer_id);
                    match (latency_to_dst, latency_to_gateway) {
                        (Some(latency_to_dst), Some(latency_to_gateway)) => {
                            let latency_thold =
                                std::cmp::max(latency_to_dst, latency_to_gateway) as f32 * 0.1;
                            let latency_diff = (latency_to_dst).abs_diff(latency_to_gateway) as f32;
                            if latency_diff < latency_thold {
                                self.cache_info
                                    .route_cache
                                    .insert((dst_peer_id, policy.clone()), Timed::new(dst_peer_id));
                                return Some(dst_peer_id);
                            }
                        }
                        _ => {}
                    }
                }
                // NOTIC: for foreign network, gateway_peer_id may not connect to me
                self.cache_info
                    .route_cache
                    .insert((dst_peer_id, policy.clone()), Timed::new(gateway_peer_id));
                return Some(gateway_peer_id);
            }
        }

        None
    }

    pub async fn list_peers_own_foreign_network(
        &self,
        network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for route in self.routes.read().await.iter() {
            let peers = route
                .list_peers_own_foreign_network(&network_identity)
                .await;
            ret.extend(peers);
        }
        ret
    }

    pub async fn send_msg(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        allow_drop_packet: bool,
    ) -> Result<(), Error> {
        let Some(gateway_peer_id) = self.get_gateway_peer_id(dst_peer_id, policy).await else {
            return Err(Error::RouteError(Some(format!(
                "peer map sengmsg no gateway for dst_peer_id: {}",
                dst_peer_id
            ))));
        };

        self.send_msg_directly(msg, gateway_peer_id, allow_drop_packet)
            .await?;
        return Ok(());
    }

    pub async fn get_peer_id_by_ipv4(&self, ipv4: &Ipv4Addr) -> Option<PeerId> {
        for route in self.routes.read().await.iter() {
            let peer_id = route.get_peer_id_by_ipv4(ipv4).await;
            if peer_id.is_some() {
                return peer_id;
            }
        }
        None
    }

    pub async fn get_peer_feature_flag(&self, peer_id: PeerId) -> Option<PeerFeatureFlag> {
        for route in self.routes.read().await.iter() {
            let feature_flag = route.get_feature_flag(peer_id).await;
            if feature_flag.is_some() {
                return feature_flag;
            };
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.peer_map.is_empty()
    }

    pub fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        for item in self.peer_map.iter() {
            let peer_id = item.key();
            ret.push(*peer_id);
        }
        ret
    }

    pub fn list_peers_with_conn(&self) -> Vec<PeerId> {
        let mut ret = Vec::new();
        let peers = self.list_peers();
        for peer_id in peers.iter() {
            let Some(peer) = self.get_peer_by_id(*peer_id) else {
                continue;
            };
            if peer.list_peer_conns().len() > 0 {
                ret.push(*peer_id);
            }
        }
        ret
    }

    pub fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            Some(p.list_peer_conns())
        } else {
            return None;
        }
    }

    pub fn get_peer_default_conn_id(&self, peer_id: PeerId) -> Option<PeerConnId> {
        self.get_peer_by_id(peer_id)
            .and_then(|p| p.get_default_conn())
            .map(|conn| conn.get_conn_id())
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        if let Some(p) = self.get_peer_by_id(peer_id) {
            p.close_peer_conn(conn_id).await
        } else {
            return Err(Error::NotFound);
        }
    }

    pub fn close_peer(&self, peer_id: PeerId) -> Result<(), TunnelError> {
        let remove_ret = self.peer_map.remove(&peer_id);
        self.global_ctx
            .issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        tracing::info!(
            ?peer_id,
            has_old_value = ?remove_ret.is_some(),
            peer_ref_counter = ?remove_ret.map(|v| Arc::strong_count(&v.1)),
            "peer is closed"
        );
        Ok(())
    }

    pub async fn add_route(&self, route: ArcRoute) {
        let mut routes = self.routes.write().await;
        routes.insert(0, route);
    }

    pub fn clean_peer_without_conn(&self) {
        let mut to_remove = vec![];

        for peer_id in self.list_peers() {
            let conns = self.list_peer_conns(peer_id);
            if conns.is_none() || conns.as_ref().unwrap().is_empty() {
                to_remove.push(peer_id);
            }
        }

        for peer_id in to_remove {
            self.close_peer(peer_id).unwrap();
        }
    }

    pub async fn list_routes(&self) -> DashMap<PeerId, PeerId> {
        let route_map = DashMap::new();
        for route in self.routes.read().await.iter() {
            for item in route.list_routes().await.iter() {
                route_map.insert(item.peer_id, item.next_hop_peer_id);
            }
        }
        route_map
    }

    pub async fn need_relay_by_foreign_network(&self, dst_peer_id: PeerId) -> Result<bool, Error> {
        // if gateway_peer_id is not connected to me, means need relay by foreign network
        let gateway_id = self
            .get_gateway_peer_id(dst_peer_id, NextHopPolicy::LeastHop)
            .await
            .ok_or(Error::RouteError(Some(format!(
                "peer map need_relay_by_foreign_network no gateway for dst_peer_id: {}",
                dst_peer_id
            ))))?;

        Ok(!self.has_peer(gateway_id))
    }

    pub fn get_alive_conns(&self) -> DashMap<(PeerId, PeerConnId), PeerConnInfo> {
        self.alive_conns
            .iter()
            .map(|v| (v.key().clone(), v.value().clone()))
            .collect()
    }

    pub fn has_directly_connected_conn_as(&self, peer_id: PeerId, as_client: bool) -> Option<bool> {
        let Some(peer) = self.get_peer_by_id(peer_id) else {
            return None;
        };
        for conn in peer.list_peer_conns() {
            if conn.is_client == as_client {
                return Some(true);
            }
        }
        Some(false)
    }
}

impl Drop for PeerMap {
    fn drop(&mut self) {
        tracing::debug!(
            self.my_peer_id,
            network = ?self.global_ctx.get_network_identity(),
            "PeerMap is dropped"
        );
    }
}
