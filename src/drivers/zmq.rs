use std::sync::Mutex;
use std::thread;

use crate::Error;
use crate::interfaces::{InterfaceID, zmq::ZmqInterfaceDriver};

/// ZeroMQ PUB/SUB driver for a CSP hub.
///
/// The publisher connects to the hub's SUB endpoint (port 6000 by default),
/// while the subscriber connects to the hub's PUB endpoint (port 7000).
pub struct ZmqDriver {
    _context: zmq::Context,
    publisher: Mutex<zmq::Socket>,
    subscriber: Mutex<Option<zmq::Socket>>,
}

impl ZmqDriver {
    /// Connect to the default hub ports at `host`.
    pub fn connect(host: &str) -> Result<Self, zmq::Error> {
        let publish_port = crate::interfaces::zmq::ZMQPROXY_SUBSCRIBE_PORT;
        let subscribe_port = crate::interfaces::zmq::ZMQPROXY_PUBLISH_PORT;
        Self::connect_endpoints(
            &std::format!("tcp://{host}:{publish_port}"),
            &std::format!("tcp://{host}:{subscribe_port}"),
        )
    }

    /// Connect to explicit publisher and subscriber endpoints.
    pub fn connect_endpoints(
        publish_endpoint: &str,
        subscribe_endpoint: &str,
    ) -> Result<Self, zmq::Error> {
        let context = zmq::Context::new();
        let publisher = context.socket(zmq::PUB)?;
        let subscriber = context.socket(zmq::SUB)?;
        publisher.set_linger(0)?;
        subscriber.set_linger(0)?;
        subscriber.set_maxmsgsize(u16::MAX as i64)?;
        subscriber.set_subscribe(b"")?;
        publisher.connect(publish_endpoint)?;
        subscriber.connect(subscribe_endpoint)?;

        Ok(Self {
            _context: context,
            publisher: Mutex::new(publisher),
            subscriber: Mutex::new(Some(subscriber)),
        })
    }

    fn start_rx(&mut self, iface: InterfaceID) {
        let Some(subscriber) = self
            .subscriber
            .lock()
            .expect("ZeroMQ subscriber lock poisoned")
            .take()
        else {
            return;
        };

        let thread = thread::Builder::new()
            .name("csp-zmq-rx".into())
            .spawn(move || {
                loop {
                    match Self::receive_part(&subscriber) {
                        Ok(frame) => {
                            let mut more = match subscriber.get_rcvmore() {
                                Ok(more) => more,
                                Err(error) => {
                                    std::eprintln!("CSP ZMQ RX multipart check failed: {error}");
                                    break;
                                }
                            };
                            if more {
                                crate::interfaces::zmq::reject_multipart(iface);
                                let mut drain_failed = false;
                                while more {
                                    if let Err(error) = Self::receive_part(&subscriber) {
                                        std::eprintln!(
                                            "CSP ZMQ RX failed to drain multipart message: {error}"
                                        );
                                        drain_failed = true;
                                        break;
                                    }
                                    more = match subscriber.get_rcvmore() {
                                        Ok(more) => more,
                                        Err(error) => {
                                            std::eprintln!(
                                                "CSP ZMQ RX multipart check failed: {error}"
                                            );
                                            drain_failed = true;
                                            break;
                                        }
                                    };
                                }
                                if drain_failed {
                                    break;
                                }
                                continue;
                            }
                            if let Err(error) = crate::interfaces::zmq::receive_frame(iface, &frame)
                            {
                                std::eprintln!("CSP ZMQ RX frame rejected: {error:?}");
                            }
                        }
                        Err(error) => {
                            std::eprintln!("CSP ZMQ RX stopped: {error}");
                            break;
                        }
                    }
                }
            })
            .unwrap_or_else(|error| panic!("failed to create CSP ZMQ receive thread: {error}"));

        drop(thread);
    }

    fn receive_part(socket: &zmq::Socket) -> Result<std::vec::Vec<u8>, zmq::Error> {
        loop {
            match socket.recv_bytes(0) {
                Err(zmq::Error::EINTR) => continue,
                result => return result,
            }
        }
    }
}

impl ZmqInterfaceDriver for ZmqDriver {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        let publisher = self
            .publisher
            .lock()
            .expect("ZeroMQ publisher lock poisoned");
        publisher.send(frame, 0).map(|_| ()).map_err(|error| {
            std::eprintln!("CSP ZMQ TX error: {error}");
            Error::InvalidOperation
        })
    }

    fn spawn_rx_task(&mut self, id: InterfaceID) {
        self.start_rx(id);
    }
}
