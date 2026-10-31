//! The network server: accepts TLS connections, authenticates each request
//! against the owner's token, dispatches to a handler, and logs the outcome.

use crate::handlers::Context;
use anyhow::Result;
use fleet_common::{read_frame, tokens_match, write_frame, Request, Response, PROTOCOL_VERSION};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub async fn run(
    bind: &str,
    acceptor: TlsAcceptor,
    token: Arc<String>,
    ctx: Arc<Context>,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(bind, "fleet-agent listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = token.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer, acceptor, token, ctx).await {
                tracing::info!(%peer, error = %e, "connection ended");
            }
        });
    }
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    token: Arc<String>,
    ctx: Arc<Context>,
) -> Result<()> {
    let mut tls = acceptor.accept(stream).await?;
    let request: Request = match read_frame(&mut tls).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(%peer, error = %e, "malformed request frame");
            let _ = write_frame(&mut tls, &Response::err("malformed request")).await;
            return Ok(());
        }
    };

    if request.protocol != PROTOCOL_VERSION {
        write_frame(
            &mut tls,
            &Response::err(format!(
                "protocol mismatch: agent speaks v{PROTOCOL_VERSION}, controller sent v{}",
                request.protocol
            )),
        )
        .await?;
        return Ok(());
    }

    if !tokens_match(&request.token, &token) {
        // Do not reveal whether the token was close; log the peer for audit.
        tracing::warn!(%peer, "authentication failed");
        write_frame(&mut tls, &Response::err("authentication failed")).await?;
        return Ok(());
    }

    tracing::info!(%peer, command = ?short_name(&request), "authenticated request");
    let response = ctx.handle(request.command);
    write_frame(&mut tls, &response).await?;
    // Send a TLS close_notify so the controller sees a clean end-of-stream
    // rather than a truncated-connection error.
    let _ = tls.shutdown().await;
    Ok(())
}

fn short_name(req: &Request) -> &'static str {
    use fleet_common::Command::*;
    match req.command {
        Ping => "ping",
        SystemStatus => "system_status",
        ListServices => "list_services",
        ServiceStatus { .. } => "service_status",
        ServiceControl { .. } => "service_control",
        ListConfig => "list_config",
        GetConfig { .. } => "get_config",
        PushConfig { .. } => "push_config",
        TailLog { .. } => "tail_log",
    }
}
