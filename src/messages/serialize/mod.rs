use std::marker::PhantomData;
use std::sync::Arc;
use atlas_communication::message::Header;
use atlas_communication::reconfiguration_node::NetworkInformationProvider;
use atlas_common::ordering::Orderable;

use atlas_core::log_transfer::networking::serialize::LogTransferMessage;
use atlas_core::log_transfer::networking::signature_ver::LogTransferVerificationHelper;
use atlas_core::ordering_protocol::loggable::PersistentOrderProtocolTypes;
use atlas_core::ordering_protocol::networking::serialize::{OrderingProtocolMessage};
use atlas_core::smr::networking::serialize::DecisionLogMessage;
use atlas_smr_application::serialize::ApplicationData;

use crate::messages::{LogTransferMessageKind, LTMessage};

pub struct LTMsg<D: ApplicationData,
    OP: OrderingProtocolMessage<D>,
    POPT: PersistentOrderProtocolTypes<D, OP>,
    LS: DecisionLogMessage<D, OP, POPT>>(PhantomData<(D, OP, POPT, LS)>);

impl<D: ApplicationData, OP: OrderingProtocolMessage<D>,
    POPT: PersistentOrderProtocolTypes<D, OP>,
    LS: DecisionLogMessage<D, OP, POPT>> LogTransferMessage<D, OP> for LTMsg<D, OP, POPT, LS> {
    type LogTransferMessage = LTMessage<POPT::Proof, LS::DecLog>;

    fn verify_log_message<NI, LVH>(network_info: &Arc<NI>, header: &Header, message: Self::LogTransferMessage) -> atlas_common::error::Result< Self::LogTransferMessage>
        where NI: NetworkInformationProvider, LVH: LogTransferVerificationHelper<D, OP, NI>, {

        let seq = message.sequence_number();

        match message.into_kind() {
            LogTransferMessageKind::RequestLogState => {
                Ok(LTMessage::new(seq, LogTransferMessageKind::RequestLogState))
            }
            LogTransferMessageKind::ReplyLogState(opt) => {
                if let Some((first_seq, (last_seq, proof))) = opt {
                    let proof = POPT::verify_proof::<NI, LVH>(network_info, proof.clone())?;

                    Ok(LTMessage::new(seq, LogTransferMessageKind::ReplyLogState(Some((first_seq, (last_seq, proof))))))
                } else {
                    Ok(LTMessage::new(seq, LogTransferMessageKind::ReplyLogState(None)))
                }
            }
            LogTransferMessageKind::RequestProofs(seqs) => {
                Ok(LTMessage::new(seq, LogTransferMessageKind::RequestProofs(seqs)))
            }
            LogTransferMessageKind::ReplyLogParts( proofs) => {
                let mut proofs_cpy = Vec::with_capacity(proofs.len());

                for (seq, proof) in proofs {
                    let proof = POPT::verify_proof::<NI, LVH>(network_info, proof.clone())?;

                    proofs_cpy.push((seq, proof));
                }

                Ok(LTMessage::new(seq, LogTransferMessageKind::ReplyLogParts(proofs_cpy)))
            }
            LogTransferMessageKind::RequestLog => {
                Ok(LTMessage::new(seq, LogTransferMessageKind::RequestLog))
            }
            LogTransferMessageKind::ReplyLog(dec_log) => {
                let dec_log = LS::verify_decision_log::<NI, LVH>(network_info, dec_log.clone())?;

                Ok(LTMessage::new(seq, LogTransferMessageKind::ReplyLog(dec_log)))
            }
        }
    }

    #[cfg(feature = "serialize_capnp")]
    fn serialize_capnp(builder: atlas_capnp::lt_messages_capnp::lt_message::Builder, msg: &Self::LogTransferMessage) -> atlas_common::error::Result<()> {
        todo!()
    }

    #[cfg(feature = "serialize_capnp")]
    fn deserialize_capnp(reader: atlas_capnp::lt_messages_capnp::lt_message::Reader) -> atlas_common::error::Result<Self::LogTransferMessage> {
        todo!()
    }
}