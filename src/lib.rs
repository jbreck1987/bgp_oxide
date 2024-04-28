// This library is my naive, first attempt to write something interesting in Rust that I also find interesting. It's a very simple implementation
// of the BGP4 protocol as defined in RFC 4271. This will be dirty and rough, it's designed to be a learning experience with a protocol I'm already
// familiar with from an operator's perspective. Maybe i'll eventually implement EIGRP or OSPF...


mod message_types;
mod errors;
mod path_attrs;
mod fsm_ds;
mod fsm;
mod msg_decoder;
mod msg_encoder;
