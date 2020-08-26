use bytes::Bytes;
use futures::StreamExt;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    let builder = ServiceBuilder::default().insert_protocol(meta);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

struct PHandle {
    count: Arc<AtomicUsize>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, _context: &mut ProtocolContext) {}

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            let prefix = "abcde".repeat(800);
            // NOTE: 256 is the send channel buffer size
            let length = 1024;
            for i in 0..length {
                println!("> [Server] send {}", i);
                let _ = context.send_message(Bytes::from(format!(
                    "{}-000000000000000000000{}",
                    prefix, i
                )));
            }
        }
    }

    fn received(&mut self, context: ProtocolContextMutRef, data: Bytes) {
        let count_now = self.count.load(Ordering::SeqCst);
        if context.session.ty.is_outbound() {
            println!("> [Client] received {}", count_now);
            let _ = context.send_message(format!("xx-{}", count_now).into());
            self.count.fetch_add(1, Ordering::SeqCst);
        } else {
            println!("> [Server] received {}", String::from_utf8_lossy(&data));
        }
        if count_now + 1 == 1024 {
            let _ = context.close();
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    (
        MetaBuilder::new()
            .id(id)
            .service_handle(move || {
                if id == 0.into() {
                    ProtocolHandle::Neither
                } else {
                    let handle = Box::new(PHandle { count: count_clone });
                    ProtocolHandle::Callback(handle)
                }
            })
            .build(),
        count,
    )
}

fn main() {
    env_logger::init();
    let mut rt = tokio::runtime::Runtime::new().unwrap();

    if std::env::args().nth(1) == Some("server".to_string()) {
        rt.block_on(async move {
            let (meta, _) = create_meta(1.into());
            let mut service = create(false, meta, ());
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/8900".parse().unwrap())
                .await
                .unwrap();
            println!("listen_addr: {}", listen_addr);
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    } else {
        rt.block_on(async move {
            let listen_addr = std::env::args().nth(1).unwrap().parse().unwrap();
            let (meta, _result) = create_meta(1.into());
            let mut service = create(false, meta, ());
            service
                .dial(listen_addr, TargetProtocol::All, None)
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    }
}
