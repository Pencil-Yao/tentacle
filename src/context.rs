use bytes::Bytes;
use futures::{
    prelude::*,
    sync::{mpsc, oneshot},
};
use log::warn;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use crate::{
    multiaddr::Multiaddr,
    protocol_select::ProtocolInfo,
    secio::{PublicKey, SecioKeyPair},
    service::{event::ServiceTask, DialProtocol, ServiceControl, SessionType, TargetSession},
    session::SessionEvent,
    ProtocolId, SessionId,
};

pub(crate) struct SessionControl {
    pub(crate) inner: Arc<SessionContext>,
    pub(crate) notify_signals: HashMap<ProtocolId, HashMap<u64, oneshot::Sender<()>>>,
    pub(crate) event_sender: mpsc::Sender<SessionEvent>,
}

/// Session context, contains basic information about the current connection
#[derive(Clone, Debug)]
pub struct SessionContext {
    /// Session's ID
    pub id: SessionId,
    /// Remote socket address
    pub address: Multiaddr,
    /// Session type (server or client)
    pub ty: SessionType,
    // TODO: use reference?
    /// Remote public key
    pub remote_pubkey: Option<PublicKey>,
}

/// The Service runtime can send some instructions to the inside of the handle.
/// This is the sending channel.
// TODO: Need to maintain the network topology map here?
pub struct ServiceContext {
    listens: Vec<Multiaddr>,
    key_pair: Option<SecioKeyPair>,
    inner: ServiceControl,
}

impl ServiceContext {
    /// New
    pub(crate) fn new(
        service_task_sender: mpsc::UnboundedSender<ServiceTask>,
        quick_task_sender: mpsc::UnboundedSender<ServiceTask>,
        proto_infos: HashMap<ProtocolId, ProtocolInfo>,
        key_pair: Option<SecioKeyPair>,
        timeout: Duration,
    ) -> Self {
        ServiceContext {
            inner: ServiceControl::new(
                service_task_sender,
                quick_task_sender,
                proto_infos,
                timeout,
            ),
            key_pair,
            listens: Vec::new(),
        }
    }

    /// Create a new listener
    #[inline]
    pub fn listen(&self, address: Multiaddr) {
        if let Err(e) = self.inner.listen(address) {
            warn!("Service Error: {}", e)
        }
    }

    /// Initiate a connection request to address
    #[inline]
    pub fn dial(&self, address: Multiaddr, target: DialProtocol) {
        if let Err(e) = self.inner.dial(address, target) {
            warn!("Service Error: {}", e)
        }
    }

    /// Disconnect a connection
    #[inline]
    pub fn disconnect(&self, session_id: SessionId) {
        if let Err(e) = self.inner.disconnect(session_id) {
            warn!("Service Error: {}", e)
        }
    }

    /// Send message
    #[inline]
    pub fn send_message_to(&self, session_id: SessionId, proto_id: ProtocolId, data: Bytes) {
        if let Err(e) = self.inner.send_message_to(session_id, proto_id, data) {
            warn!("Service Error: {}", e)
        }
    }

    /// Send message on quick channel
    #[inline]
    pub fn quick_send_message_to(&self, session_id: SessionId, proto_id: ProtocolId, data: Bytes) {
        if let Err(e) = self.inner.quick_send_message_to(session_id, proto_id, data) {
            warn!("Service Error: {}", e)
        }
    }

    /// Send data to the specified protocol for the specified sessions.
    #[inline]
    pub fn filter_broadcast(&self, session_ids: TargetSession, proto_id: ProtocolId, data: Bytes) {
        if let Err(e) = self.inner.filter_broadcast(session_ids, proto_id, data) {
            warn!("Service Error: {}", e)
        }
    }

    /// Send data to the specified protocol for the specified sessions on quick channel.
    #[inline]
    pub fn quick_filter_broadcast(
        &self,
        session_ids: TargetSession,
        proto_id: ProtocolId,
        data: Bytes,
    ) {
        if let Err(e) = self
            .inner
            .quick_filter_broadcast(session_ids, proto_id, data)
        {
            warn!("Service Error: {}", e)
        }
    }

    /// Send a future task
    #[inline]
    pub fn future_task<T>(&self, task: T)
    where
        T: Future<Item = (), Error = ()> + 'static + Send,
    {
        if let Err(e) = self.inner.future_task(task) {
            warn!("Service Error: {}", e)
        }
    }

    /// Try open a protocol
    ///
    /// If the protocol has been open, do nothing
    #[inline]
    pub fn open_protocol(&self, session_id: SessionId, proto_id: ProtocolId) {
        if let Err(e) = self.inner.open_protocol(session_id, proto_id) {
            warn!("Service Error: {}", e)
        }
    }

    /// Try close a protocol
    ///
    /// If the protocol has been closed, do nothing
    #[inline]
    pub fn close_protocol(&self, session_id: SessionId, proto_id: ProtocolId) {
        if let Err(e) = self.inner.close_protocol(session_id, proto_id) {
            warn!("Service Error: {}", e)
        }
    }

    /// Get the internal channel sender side handle
    #[inline]
    pub fn control(&self) -> &ServiceControl {
        &self.inner
    }

    /// Get service protocol message, Map(ID, Name), but can't modify
    #[inline]
    pub fn protocols(&self) -> &Arc<HashMap<ProtocolId, ProtocolInfo>> {
        &self.inner.proto_infos
    }

    /// Get the key pair of self
    #[inline]
    pub fn key_pair(&self) -> Option<&SecioKeyPair> {
        self.key_pair.as_ref()
    }

    /// Get service listen address list
    #[inline]
    pub fn listens(&self) -> &[Multiaddr] {
        self.listens.as_ref()
    }

    /// Update listen list
    #[inline]
    pub(crate) fn update_listens(&mut self, address_list: Vec<Multiaddr>) {
        self.listens = address_list;
    }

    /// Set a service notify token
    pub fn set_service_notify(&self, proto_id: ProtocolId, interval: Duration, token: u64) {
        if let Err(e) = self.inner.set_service_notify(proto_id, interval, token) {
            warn!("Service Error: {}", e)
        }
    }

    /// Set a session notify token
    pub fn set_session_notify(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        interval: Duration,
        token: u64,
    ) {
        if let Err(e) = self
            .inner
            .set_session_notify(session_id, proto_id, interval, token)
        {
            warn!("Service Error: {}", e)
        }
    }

    /// Remove a service timer by a token
    pub fn remove_service_notify(&self, proto_id: ProtocolId, token: u64) {
        if let Err(e) = self.inner.remove_service_notify(proto_id, token) {
            warn!("Service Error: {}", e)
        }
    }

    /// Remove a session timer by a token
    pub fn remove_session_notify(&self, session_id: SessionId, proto_id: ProtocolId, token: u64) {
        if let Err(e) = self
            .inner
            .remove_session_notify(session_id, proto_id, token)
        {
            warn!("Service Error: {}", e)
        }
    }

    /// Close service.
    ///
    /// Order:
    /// 1. close all listens
    /// 2. try close all session's protocol stream
    /// 3. try close all session
    /// 4. close service
    pub fn close(&self) {
        if let Err(e) = self.inner.close() {
            warn!("Service Error: {}", e)
        }
    }

    /// Shutdown service, don't care anything, may cause partial message loss
    pub fn shutdown(&self) {
        if let Err(e) = self.inner.shutdown() {
            warn!("Service Error: {}", e)
        }
    }

    pub(crate) fn clone_self(&self) -> Self {
        ServiceContext {
            inner: self.inner.clone(),
            key_pair: self.key_pair.clone(),
            listens: self.listens.clone(),
        }
    }
}

/// Protocol handle context
pub struct ProtocolContext {
    inner: ServiceContext,
    /// Protocol id
    pub proto_id: ProtocolId,
}

impl ProtocolContext {
    pub(crate) fn new(service_context: ServiceContext, proto_id: ProtocolId) -> Self {
        ProtocolContext {
            inner: service_context,
            proto_id,
        }
    }

    #[inline]
    pub(crate) fn as_mut<'a, 'b: 'a>(
        &'b mut self,
        session: &'a SessionContext,
    ) -> ProtocolContextMutRef<'a> {
        ProtocolContextMutRef {
            inner: self,
            session,
        }
    }
}

/// Protocol handle context contain session context
pub struct ProtocolContextMutRef<'a> {
    inner: &'a mut ProtocolContext,
    /// Session context
    pub session: &'a SessionContext,
}

impl<'a> ProtocolContextMutRef<'a> {
    /// Send message to current protocol current session
    #[inline]
    pub fn send_message(&self, data: Bytes) {
        let proto_id = self.proto_id();
        self.inner.send_message_to(self.session.id, proto_id, data)
    }

    /// Send message to current protocol current session on quick channel
    #[inline]
    pub fn quick_send_message(&self, data: Bytes) {
        let proto_id = self.proto_id();
        self.inner
            .quick_send_message_to(self.session.id, proto_id, data)
    }

    /// Protocol id
    #[inline]
    pub fn proto_id(&self) -> ProtocolId {
        self.inner.proto_id
    }
}

impl Deref for ProtocolContext {
    type Target = ServiceContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ProtocolContext {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a> Deref for ProtocolContextMutRef<'a> {
    type Target = ProtocolContext;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> DerefMut for ProtocolContextMutRef<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
