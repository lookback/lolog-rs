#[macro_use]
extern crate tracing;

use std::convert::TryInto;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::{env, fmt, process};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rustls::pki_types::{InvalidDnsNameError, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;
use serde_json::{Map, Value};
use tracing::span::Attributes;
use tracing::{field, Event, Span, Subscriber};
use tracing_core::span::{Id, Record};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{prelude::*, registry::LookupSpan};

mod visitor;

pub struct LogConfig {
    /// Name of application. This is the default `namespace` in log messages. Can be appended
    /// to, compare `ios` vs `ios.bcast`. It is also used as `api_key_name`.
    pub app_name: String,
    /// Hostname of syslog entries from this instance. Default is OS hostname.
    pub hostname: String,
    /// Env of syslog entries. Default is the ENV variable, and otherwise "development".
    pub env: String,
    /// Process id.
    pub pid: u32,
    /// Application version string.
    pub app_version: String,
    /// API key id for the api key
    pub api_key_id: String,
    /// API key for loggin to our syslog server.
    pub api_key: String,
    /// Name of host to connect and deliver log messages to.
    pub log_host: String,
    /// Port on host to deliver log messages to.
    pub log_port: u16,
    /// Whether we are to use TLS for logging.
    pub use_tls: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            hostname: env::var("SYSLOG_HOSTNAME").unwrap_or_else(|_| {
                hostname::get()
                    .map(|o| o.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "<hostname>".into())
            }),
            env: env::var("ENV").unwrap_or_else(|_| "development".to_string()),
            pid: process::id(),
            app_name: "<app name>".into(),
            app_version: "<app version>".into(),
            api_key_id: env::var("SYSLOG_API_KEY_ID").unwrap_or_else(|_| "".into()),
            api_key: env::var("SYSLOG_API_KEY").unwrap_or_else(|_| "".into()),
            log_host: env::var("SYSLOG_HOST")
                .unwrap_or_else(|_| "logrelay.lookback.io".to_string()),
            log_port: env::var("SYSLOG_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6514),
            use_tls: env::var("SYSLOG_TLS")
                .map(|x| x == "1" || x == "true")
                .unwrap_or(false),
        }
    }
}

/// Logging implementation for tracing crate.
pub struct Logger {
    /// The config of the logging system.
    config: Arc<LogConfig>,
    /// Base record with fields that don't change.
    base_record: Arc<LogRecord>,
}

impl Logger {
    pub fn init(config: LogConfig) -> Result<(), Error> {
        assert!(config.use_tls, "Must use TLS for logging");

        let config = Arc::new(config);

        let base_record = Arc::new(LogRecord {
            facility: Arc::new(SyslogFacility::Local1),
            hostname: Arc::new(config.hostname.clone()),
            app_name: Arc::new(config.app_name.clone()),
            pid: config.pid,
            api_key_id: Arc::new(if config.api_key_id.is_empty() {
                config.app_name.clone()
            } else {
                config.api_key_id.clone()
            }),
            api_key: Arc::new(config.api_key.clone()),
            env: Arc::new(config.env.clone()),

            severity: SyslogSeverity::Informational,
            msg_id: "".to_string(),
            timestamp: Utc::now(),
            message: None,
            well_known: None,
        });

        let logger = Logger {
            config,
            base_record,
        };

        // Compose our logger layer with the "EnvFilter" which is set via
        // RUST_LOG=xxx standard syntax.
        let filter = EnvFilter::from_default_env();
        let filtered_logger = logger.with_filter(filter);
        let subscriber = tracing_subscriber::registry().with(filtered_logger);

        #[cfg(feature = "tokio_console")]
        let subscriber = subscriber.with(console_subscriber::spawn());

        tracing_core::dispatcher::set_global_default(tracing_core::dispatcher::Dispatch::new(
            subscriber,
        ))
        .expect("Setting global logger dispatcher");

        Ok(())
    }
}

impl<S> Layer<S> for Logger
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");

        let mut extensions = span.extensions_mut();

        if extensions.get_mut::<Map<String, Value>>().is_none() {
            let mut object = Map::with_capacity(16);
            let mut visitor = visitor::AdditionalFieldVisitor::new(&mut object);
            attrs.record(&mut visitor);
            extensions.insert(object);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span not found, this is a bug");

        let mut extensions = span.extensions_mut();

        if let Some(object) = extensions.get_mut::<Map<String, Value>>() {
            let mut add_field_visitor = visitor::AdditionalFieldVisitor::new(object);
            values.record(&mut add_field_visitor);
        } else {
            let mut object = Map::with_capacity(16);
            let mut add_field_visitor = visitor::AdditionalFieldVisitor::new(&mut object);
            values.record(&mut add_field_visitor);
            extensions.insert(object)
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut record = (*self.base_record).clone();
        let mut json = Map::with_capacity(16);
        record.timestamp = Utc::now();

        let scope = ctx.event_scope(event);

        if let Some(scope) = scope {
            // TODO:it's unclear whether we want to log the span names.
            let _spans = scope.fold(String::new(), |mut spans, span| {
                // Add fields captured in spans to the json object.
                if let Some(span_object) = span.extensions().get::<Map<String, Value>>() {
                    json.extend(span_object.clone());
                }

                if !spans.is_empty() {
                    spans = format!("{}:{}", spans, span.name());
                } else {
                    spans = span.name().to_string();
                }

                spans
            });
        }

        let metadata = event.metadata();

        record.severity = match *metadata.level() {
            tracing_core::Level::ERROR => SyslogSeverity::Error,
            tracing_core::Level::WARN => SyslogSeverity::Warning,
            tracing_core::Level::INFO => SyslogSeverity::Informational,
            tracing_core::Level::DEBUG => SyslogSeverity::Debug,
            tracing_core::Level::TRACE => SyslogSeverity::Trace,
        };

        // Data saved in the event itself.
        let mut add_field_visitor = visitor::AdditionalFieldVisitor::new(&mut json);
        event.record(&mut add_field_visitor);

        if let Some(subsys) = json.remove("subsys") {
            record.app_name = Arc::new(format!("{}.{}", self.config.app_name, subsys.as_string()));
        }

        trait ToStr {
            fn as_string(&self) -> String;
        }

        impl ToStr for Value {
            fn as_string(&self) -> String {
                match self {
                    Value::Bool(v) => format!("{}", v),
                    Value::Number(v) => format!("{}", v),
                    Value::String(v) => v.clone(),
                    _ => panic!("Unexpected value {:?}", self),
                }
            }
        }

        // "message" is recorded as a separate field in tracig, but goes in separate field
        // in our own logging.
        record.message = json.remove("message").map(|v| v.as_string());

        // Rows bridged in from "log" crate via tracing-log have these additional properties.
        // "log.file":"/Users/martin/.cargo/registry/src/github.com-1ecc6299db9ec823/webrtc-dtls-0.5.1/src/handshake/handshake_message_client_hello.rs"
        // "log.line":172
        // "log.module_path":"webrtc_dtls::handshake::handshake_message_client_hello"
        // "log.target":"webrtc_dtls::handshake::handshake_message_client_hello"

        if let Some(target) = json.remove("log.target") {
            if let Some(message) = record.message {
                record.message = Some(format!("{} {}", target.as_string(), message));
            } else {
                record.message = Some(target.as_string());
            }
        }

        // Strip all "log." properties since we don't want that messing up the output
        json.retain(|k, _| !k.starts_with("log."));

        if !json.is_empty() {
            // Values that goes into WellKnown.
            let mut wk = WellKnown {
                recordingId: json.remove("recordingId").map(|v| v.as_string()),
                userId: json.remove("userId").map(|v| v.as_string()),
                teamId: json.remove("teamId").map(|v| v.as_string()),
                userIp: json.remove("userIp").map(|v| v.as_string()),
                sessionId: json.remove("sessionId").map(|v| v.as_string()),
                metricGroup: json.remove("metricGroup").map(|v| v.as_string()),

                ..Default::default()
            };

            // TODO: Explore using `tracing`'s `Valuable` trait instead of this when it becomes
            // stable.
            if let Some(Value::String(raw_json)) = json.remove("json") {
                let parse_result = serde_json::from_str(&raw_json);

                if let Ok(Value::Object(parsed_json_object)) = parse_result {
                    // If there's a "json" field we expect it to be a serailized JSON object.
                    // We merge this object into the structured data that we include in syslog
                    json.merge_into(&parsed_json_object);
                }
            }

            // Rest is data
            if !json.is_empty() {
                wk.data = Some(json);
            }

            record.well_known = Some(wk);
        }

        let log_host = self.config.log_host.as_str();
        let log_port = self.config.log_port;
        handle_log_record(log_host, log_port, record);
    }
}

#[derive(Debug, Clone)]
struct LogRecord {
    facility: Arc<SyslogFacility>,
    hostname: Arc<String>,
    app_name: Arc<String>,
    pid: u32,
    api_key_id: Arc<String>,
    api_key: Arc<String>,
    env: Arc<String>,

    severity: SyslogSeverity,
    msg_id: String,
    timestamp: DateTime<Utc>,
    message: Option<String>,
    well_known: Option<WellKnown>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
#[allow(non_snake_case)]
pub struct WellKnown {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recordingId: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub userId: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub teamId: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub userIp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sessionId: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metricGroup: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Map<String, Value>>,
}

impl WellKnown {
    pub fn info_span(&self, name: &str) -> Span {
        let span = info_span!(
            "{}",
            name,
            // To allow fields to be set late (after the span is created), using record_in_span below,
            // we must declare all the fields that we intend to record late.
            recordingId = field::Empty,
            userId = field::Empty,
            teamId = field::Empty,
            userIp = field::Empty,
            sessionId = field::Empty,
            metricGroup = field::Empty,
        );

        self.record_in_span(&span);

        span
    }

    pub fn record_in_current(&self) {
        self.record_in_span(&Span::current());
    }

    fn record_in_span(&self, span: &Span) {
        if let Some(v) = &self.recordingId {
            span.record("recordingId", &v.as_str());
        }
        if let Some(v) = &self.userId {
            span.record("userId", &v.as_str());
        }
        if let Some(v) = &self.teamId {
            span.record("teamId", &v.as_str());
        }
        if let Some(v) = &self.userIp {
            span.record("userIp", &v.as_str());
        }
        if let Some(v) = &self.sessionId {
            span.record("sessionId", &v.as_str());
        }
        if let Some(v) = &self.metricGroup {
            span.record("metricGroup", &v.as_str());
        }
    }
}

// singleton log connection.
static LOG_CONN: Lazy<Mutex<Option<StreamOwned<ClientConnection, TcpStream>>>> =
    Lazy::new(|| Mutex::new(None));

/// Send messages to log server
fn handle_log_record(log_host: &str, log_port: u16, r: LogRecord) {
    use colorful::Color;
    use colorful::Colorful;

    let color = {
        use SyslogSeverity::*;
        match r.severity {
            Emergency | Alert | Critical | Error => Color::Red,
            Warning => Color::Yellow,
            Notice => Color::Purple3,
            Informational => Color::Green3a,
            Debug => Color::CadetBlue1,
            Trace => Color::Pink3,
        }
    };

    // The SYSLOG_API_KEY env var goes into this field, and is the best implicit way to detect
    // that we want to send to the log host. An alternative would be to implement a direct
    // config option like "disable_console".
    let send_to_host = !r.api_key.is_empty();
    // Don't log telemetry
    let should_log = !r.app_name.ends_with(".telemetry");

    // don't log to console when we are sending to host, this to avoid double logging when
    // deployed in frontloader which also forwards console to the log servers.
    if !send_to_host && should_log {
        let row_color = format!(
            "{} {}  {} {}",
            r.timestamp.format("%H:%M:%S%.3f"),
            format!("{:5}", r.severity.to_string()).color(color).bold(),
            r.message.as_deref().unwrap_or(""),
            if let Some(wk) = &r.well_known {
                serde_json::to_string(&wk).expect("json serialize")
            } else {
                "".to_string()
            },
        );

        eprintln!("{}", row_color);

        return;
    }

    if r.severity >= SyslogSeverity::Trace {
        // Never log TRACE to the log server.
        return;
    }

    let mut log_conn = LOG_CONN.lock().unwrap();

    // reconnect loop
    loop {
        // Connect up TLS connection to log server.
        if log_conn.is_none() {
            match connect(log_host, log_port) {
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

        let str = r.to_string();
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

///
/// Standardized codes: https://www.notion.so/lookback/2883ab4e80914944b25a065154c554dd?v=66e7cb924934474aae5996448a870367
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Abort {
    Clean = 0,
    MissingEnvVar = 10,
    UncaughtException = 11,
    DatabaseError = 12,
    LoggingError = 13,
    SideboatInitError = 14,
    ProhibitedSyscall = 15,
    PermissionDenied = 16,
    OutOfMemory = 17,
}

impl Abort {
    pub fn abort(self, msg: &str) -> ! {
        let code = self as i32;
        let msg = format!("({}): {}", code, msg);
        if self == Abort::Clean {
            info!("{}", msg);
        } else {
            warn!("{}", msg);
        }
        eprintln!("{}", msg);
        let mut lock = LOG_CONN.lock().unwrap();
        if let Some(socket) = &mut *lock {
            socket.flush().ok();
        }
        // run drop handler
        let _ = lock.take();
        // hold lock until exit
        std::process::exit(code);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyslogFacility {
    Kernel = 0,
    User = 1,
    System = 3,
    Audit = 13,
    Alert = 14,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
    Trace = 8, // not a valid syslog value
}

impl fmt::Display for SyslogSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SyslogSeverity::Emergency => "EMERG",
                SyslogSeverity::Alert => "ALERT",
                SyslogSeverity::Critical => "CRIT",
                SyslogSeverity::Error => "ERROR",
                SyslogSeverity::Warning => "WARN",
                SyslogSeverity::Notice => "NOTICE",
                SyslogSeverity::Informational => "INFO",
                SyslogSeverity::Debug => "DEBUG",
                SyslogSeverity::Trace => "TRACE",
            }
        )
    }
}

/// Format as a syslog row.
#[allow(clippy::write_with_newline)]
impl fmt::Display for LogRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pri = (*self.facility as u8) * 8 + (self.severity as u8);

        // 2019-03-18T13:12:27.000+00:00
        let time = self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3f%:z");

        // 53595 is an private enterprise number (PEN) for Lookback
        // as assigned by IANA. https://www.iana.org/assignments/enterprise-numbers
        // we applied for it here:
        // https://pen.iana.org/pen/PenApplication.page
        let strct = format!(
            "[{}@53595 apiKey=\"{}\" env=\"{}\"]",
            self.api_key_id, self.api_key, self.env
        );

        let mut message = self
            .message
            .as_deref()
            .map(|s| s.trim())
            .unwrap_or("")
            .to_owned();

        if let Some(w) = &self.well_known {
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

        write!(
            f,
            "<{}>1 {} {} {} {} {} {} {}\n",
            pri,
            time,
            chk(&*self.hostname),
            chk(&*self.app_name),
            self.pid,
            chk(&self.msg_id),
            strct,
            chk(&message),
        )
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::Error),
    Dns(InvalidDnsNameError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Tls(e) => write!(f, "{}", e),
            Error::Dns(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Tls(e) => Some(e),
            Error::Dns(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<InvalidDnsNameError> for Error {
    fn from(e: InvalidDnsNameError) -> Self {
        Error::Dns(e)
    }
}

trait MergeMap {
    fn merge_into(&mut self, other: &Self);
}

impl MergeMap for Map<String, Value> {
    /// Merge one map into another.
    ///
    /// Keys in the second argument overwrite those in the first.
    /// NB: This isn't recursive
    fn merge_into(&mut self, other: &Self) {
        for (key, value) in other.iter() {
            self.entry(key)
                .and_modify(|e| {
                    *e = value.clone();
                })
                .or_insert(value.clone());
        }
    }
}

#[cfg(test)]
mod test {
    use chrono::NaiveDateTime;

    use super::*;

    #[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
    struct RandomStuff {
        stuff: usize,
    }

    #[test]
    fn translate_syslog() {
        let mut data = Map::new();
        data.insert(
            "extra".into(),
            serde_json::to_value(&RandomStuff { stuff: 42 }).unwrap(),
        );

        let well_known = WellKnown {
            recordingId: Some("abc123".into()),
            userId: Some("martin".into()),
            sessionId: Some("my session".into()),
            data: Some(data),
            ..Default::default()
        };

        #[allow(deprecated)]
        let n = NaiveDateTime::from_timestamp(1632152181, 392_000_000);

        let rec = LogRecord {
            facility: Arc::new(SyslogFacility::Local1),
            hostname: Arc::new("my-host".to_string()),
            app_name: Arc::new("fumar".to_string()),
            pid: 123,
            api_key_id: Arc::new("apikey".to_string()),
            api_key: Arc::new("secret stuffz".to_string()),
            env: Arc::new("development".to_string()),

            severity: SyslogSeverity::Informational,
            msg_id: "msgid".to_string(),

            #[allow(deprecated)]
            timestamp: DateTime::from_utc(n, Utc),
            message: Some("Hello world!".to_string()),
            well_known: Some(well_known),
        };

        let row = format!("{}", rec);
        assert_eq!(
            row,
            "<142>1 2021-09-20T15:36:21.392+00:00 my-host fumar \
            123 msgid [apikey@53595 apiKey=\"secret stuffz\" env=\"development\"] \
             Hello world! {\"recordingId\":\"abc123\",\"userId\":\"martin\",\
             \"sessionId\":\"my session\",\"data\":{\"extra\":{\"stuff\":42}}}\n"
        );
    }
}
