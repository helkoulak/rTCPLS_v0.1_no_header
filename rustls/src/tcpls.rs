/// This module contains optional APIs for implementing TCPLS TLS.
use crate::cipher::{Iv, IvLen};
use crate::client::{ClientConfig, ClientConnectionData, ServerName};
use crate::common_state::{CommonState, Protocol, Side};
use crate::conn::{ConnectionCore, SideData};
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::Error;
use crate::msgs::handshake::{ClientExtension, ServerExtension};
use crate::server::{ServerConfig, ServerConnectionData};
use crate::suites::BulkAlgorithm;
use crate::tls13::key_schedule::hkdf_expand;
use crate::tls13::{Tls13CipherSuite, TLS13_AES_128_GCM_SHA256_INTERNAL};

use ring::{aead, hkdf};

use std::collections::VecDeque;
use std::fmt::{self, Debug};
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use crate::ConnectionCommon;


/// A TCPLS client or server connection.
#[derive(Debug)]
pub enum Connection {
    /// A client connection
    Client(ClientConnection),
    /// A server connection
    Server(ServerConnection),
}


/// A TCPLS client connection.
pub struct ClientConnection {
    inner: ConnectionCommon<ClientConnectionData>,
}

impl ClientConnection {
    /// Make a new TCPLS ClientConnection.
    pub fn new(
        config: Arc<ClientConfig>,
        name: ServerName,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }

        let ext = ClientExtension::TCPLS;

        Ok(Self {
            inner: ConnectionCore::for_client(config, name, vec![ext], Protocol::Tcpls)?.into(),
        })
    }

}

impl Deref for ClientConnection {
    type Target = ConnectionCommon<ClientConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ClientConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ClientConnection")
            .finish()
    }
}
impl From<ClientConnection> for Connection {
    fn from(c: ClientConnection) -> Self {
        Self::Client(c)
    }
}

/// A TCPLS server connection.
pub struct ServerConnection {
    inner: ConnectionCommon<ServerConnectionData>,
}

impl ServerConnection {
    /// Make a new TCPLS ServerConnection.
    pub fn new(
        config: Arc<ServerConfig>,
    ) -> Result<Self, Error> {
        if !config.supports_version(ProtocolVersion::TLSv1_3) {
            return Err(Error::General(
                "TLS 1.3 support is required for TCPLS".into(),
            ));
        }


        let ext = ServerExtension::TCPLS;

        let mut core = ConnectionCore::for_server(config, vec![ext])?;
        core.common_state.protocol = Protocol::Tcpls;
        Ok(Self { inner: core.into() })
    }
}
impl Deref for ServerConnection {
    type Target = ConnectionCommon<ServerConnectionData>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Debug for ServerConnection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("tcpls::ServerConnection")
            .finish()
    }
}
impl From<ServerConnection> for Connection {
    fn from(c: ServerConnection) -> Self {
        Self::Server(c)
    }
}
