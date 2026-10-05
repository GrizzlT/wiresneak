use iroh::{PublicKey, endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks, VarInt}};

#[derive(Debug)]
pub struct AcceptHook {
    keys: Vec<PublicKey>,
}

impl AcceptHook {
    pub fn new(keys: Vec<PublicKey>) -> Self {
        Self {
            keys,
        }
    }
}

impl EndpointHooks for AcceptHook {
    async fn after_handshake(
        &self,
        conn: &Connection,
    ) -> AfterHandshakeOutcome {
        if self.keys.contains(&conn.remote_id()) {
            AfterHandshakeOutcome::accept()
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(403),
                reason: b"Permission denied".into(),
            }
        }
    }
}
