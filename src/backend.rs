use std::sync::Arc;

use crate::{Error, LogRecord};

/// A log backend
#[derive(Clone)]
pub struct Backend {
    inner: Arc<Inner>,
}

enum Inner {
    Network(network::Network),
    System(system::System),
}

impl Backend {
    pub(crate) fn network(host: String, port: u16, api_key_id: String, api_key: String) -> Self {
        let n = network::Network::new(host, port, api_key_id, api_key);
        Self {
            inner: Arc::new(Inner::Network(n)),
        }
    }

    pub(crate) fn system() -> Result<Self, Error> {
        system::System::new().map(|s| Self {
            inner: Arc::new(Inner::System(s)),
        })
    }

    pub(crate) fn active(&self) -> bool {
        match &*self.inner {
            Inner::Network(n) => n.active(),
            Inner::System(s) => s.active(),
        }
    }
    /// Log the record.
    pub(crate) fn log(&self, record: &LogRecord) {
        match &*self.inner {
            Inner::Network(n) => n.log(record),
            Inner::System(s) => s.log(record),
        }
    }

    pub(crate) fn flush(&self) -> Result<(), Error> {
        match &*self.inner {
            Inner::Network(n) => n.flush(),
            Inner::System(s) => s.flush(),
        }
    }
}

mod network {
    use std::io::Write;
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use crate::{Error, LogRecord};

    pub struct Network {
        conn: Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>,
        api_key: String,
        api_key_id: String,
        host: String,
        port: u16,
    }

    impl Network {
        pub fn new(host: String, port: u16, api_key_id: String, api_key: String) -> Self {
            Self {
                conn: Mutex::new(None),
                api_key,
                api_key_id,
                host,
                port,
            }
        }

        pub(super) fn active(&self) -> bool {
            !self.api_key.is_empty()
        }

        pub(super) fn log(&self, record: &crate::LogRecord) {
            let mut log_conn = self.conn.lock().unwrap();

            // reconnect loop
            loop {
                // Connect up TLS connection to log server.
                if log_conn.is_none() {
                    match connect(&self.host, self.port) {
                        Ok(v) => {
                            *log_conn = Some(v);
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to log host: {:?}", e);

                            // TODO: Do we need backoff here? Since the logging is sync, it
                            // would lock up the callsite.

                            continue;
                        }
                    }
                }

                let str = self.log_record_to_string(record);
                let bytes = str.as_bytes();

                let stream = log_conn.as_mut().expect("Existing log connection");

                match stream.write_all(bytes).and_then(|_| stream.flush()) {
                    Ok(_) => {
                        // Log message sent successfully.
                        break;
                    }
                    Err(e) => {
                        eprintln!("Log connection failed: {:?}", e);

                        // Remove previous failed connection to trigger reconnect.
                        *log_conn = None;
                    }
                }
            }
        }

        fn log_record_to_string(&self, record: &LogRecord) -> String {
            let mut res = String::new();

            let pri = (*record.facility as u8) * 8 + (record.severity as u8);

            // 2019-03-18T13:12:27.000+00:00
            let time = record.timestamp.format("%Y-%m-%dT%H:%M:%S%.3f%:z");

            // 53595 is an private enterprise number (PEN) for Lookback
            // as assigned by IANA. https://www.iana.org/assignments/enterprise-numbers
            // we applied for it here:
            // https://pen.iana.org/pen/PenApplication.page
            let strct = format!(
                "[{}@53595 apiKey=\"{}\" env=\"{}\"]",
                self.api_key_id, self.api_key, record.env
            );

            let mut message = record
                .message
                .as_deref()
                .map(|s| s.trim())
                .unwrap_or("")
                .to_owned();

            if let Some(w) = &record.well_known {
                let s = serde_json::to_string(&w).expect("Json serialize");
                message.push(' ');
                message.push_str(&s);
            }

            // replace any char < 32 with a space.
            fn strip_ctrl(s: &str) -> String {
                s.chars()
                    .map(|c| match c {
                        '\x00'..='\x1f' => ' ',
                        _ => c,
                    })
                    .collect()
            }

            message = strip_ctrl(&message);

            fn chk(s: &str) -> &str {
                if s.is_empty() {
                    "-"
                } else {
                    s
                }
            }

            use std::fmt::Write;
            let write_res = write!(
                res,
                "<{}>1 {} {} {} {} {} {} {}\n",
                pri,
                time,
                chk(&*record.hostname),
                chk(&*record.app_name),
                record.pid,
                chk(&record.msg_id),
                strct,
                chk(&message),
            );
            assert!(write_res.is_ok(), "Failed to write to string");

            res
        }

        pub(crate) fn flush(&self) -> Result<(), Error> {
            let mut log_conn = self.conn.lock().unwrap();

            if let Some(stream) = log_conn.as_mut() {
                stream.flush()?;
            }

            Ok(())
        }
    }

    /// Connect a TLS connection to the log server.
    fn connect(
        log_host: &str,
        log_port: u16,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, Error> {
        let addr = format!("{}:{}", log_host, log_port);

        let sock = TcpStream::connect(&addr)?;

        let mut root_store = RootCertStore::empty();
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .map(|ta| ta.to_owned()),
        );

        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name: ServerName = log_host.try_into()?;
        let conn = ClientConnection::new(Arc::new(tls_config), server_name.to_owned())?;

        let stream = StreamOwned::new(conn, sock);

        Ok(stream)
    }
}

mod system {
    use std::fmt;
    use std::ops::DerefMut;
    use std::os::unix::net::UnixDatagram;
    use std::sync::Mutex;

    use crate::Error;

    pub struct System {
        socket_and_buf: Mutex<(UnixDatagram, Vec<u8>)>,
    }

    impl System {
        pub fn new() -> Result<Self, Error> {
            let socket = create_socket()?;

            Ok(Self {
                socket_and_buf: Mutex::new((socket, Vec::with_capacity(1024 * 10))),
            })
        }

        pub(super) fn active(&self) -> bool {
            true
        }

        pub(super) fn log(&self, record: &crate::LogRecord) {
            use std::io::Write;
            let pri = (*record.facility as u8) * 8 + (record.severity as u8);

            let app_name = chk(record.app_name.as_str());
            let pid = record.pid;
            let msg = StripCtrl::new(record.message.as_ref().map(|s| s.as_str()).unwrap_or(""));
            let mut socket_and_buf = self.socket_and_buf.lock().unwrap();
            let (socket, buf) = socket_and_buf.deref_mut();

            // Clear out the buffer
            buf.clear();

            write!(buf, r#"<{pri}>{app_name}[{pid}]: {msg}"#)
                .expect("Write to buffer failed, out of memory?");

            if let Some(w) = &record.well_known {
                write!(buf, " ").expect("Write to buffer, out of memory?");
                serde_json::to_writer(&mut *buf, w).expect("JSON serialize");
            }
            write!(buf, "\n").expect("Write to buffer, out of memory?");

            loop {
                let res = socket.send(&buf);

                match res {
                    Ok(_) => break,
                    Err(e) => {
                        eprintln!("Failed to send log message: {:?}", e);

                        loop {
                            match create_socket() {
                                Ok(new_socket) => {
                                    *socket = new_socket;
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("Failed to create new socket: {:?}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        pub(crate) fn flush(&self) -> Result<(), Error> {
            let mut socket_and_buf = self.socket_and_buf.lock().unwrap();
            let (socket, _) = socket_and_buf.deref_mut();

            socket.shutdown(std::net::Shutdown::Write)?;

            Ok(())
        }
    }

    fn create_socket() -> Result<UnixDatagram, Error> {
        let socket = UnixDatagram::unbound()?;

        socket.connect("/dev/log")?;

        Ok(socket)
    }

    struct StripCtrl<T>(T);

    impl<T: fmt::Display> fmt::Display for StripCtrl<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use fmt::Write;
            // Custom writing mechanism that replaces control characters on-the-fly
            struct ControlSanitizer<'a, 'b> {
                formatter: &'a mut fmt::Formatter<'b>,
            }

            impl<'a, 'b> fmt::Write for ControlSanitizer<'a, 'b> {
                fn write_str(&mut self, s: &str) -> fmt::Result {
                    for c in s.chars() {
                        self.formatter
                            .write_char(if c.is_control() { ' ' } else { c })?;
                    }

                    Ok(())
                }

                fn write_char(&mut self, c: char) -> fmt::Result {
                    self.formatter
                        .write_char(if c.is_control() { ' ' } else { c })
                }
            }

            let mut sanitizer = ControlSanitizer { formatter: f };

            write!(sanitizer, "{}", self.0)
        }
    }

    impl<T: fmt::Display> StripCtrl<T> {
        fn new(value: T) -> Self {
            StripCtrl(value)
        }
    }

    fn chk(s: &str) -> &str {
        if s.is_empty() {
            "-"
        } else {
            s
        }
    }
}
