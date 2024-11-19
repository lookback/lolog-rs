#[macro_use]
extern crate tracing;

use std::ffi::NulError;
use std::io::{self};
use std::sync::{Arc, Mutex};
use std::{env, fmt, process};

use backend::Backend;
use chrono::{DateTime, Utc};
use rustls::pki_types::InvalidDnsNameError;
use serde::Serialize;
use serde_json::{Map, Value};
use tracing::span::Attributes;
use tracing::{field, Event, Span, Subscriber};
use tracing_core::span::{Id, Record};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{prelude::*, registry::LookupSpan};

mod backend;
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
    /// Backend configuration
    pub backend: Option<BackendConfig>,
}

/// Configuration for logging backend
pub enum BackendConfig {
    /// Log over the network against a server that implements the TCP protocol.
    Network(NetworkConfig),
    /// Log using a system logger.
    System {},
}

impl BackendConfig {
    pub fn as_network_mut(&mut self) -> Option<&mut NetworkConfig> {
        match self {
            BackendConfig::Network(cfg) => Some(cfg),
            _ => None,
        }
    }
}

pub struct NetworkConfig {
    host: String,
    port: u16,
    api_key: String,
    api_key_id: String,
    use_tls: bool,
}

impl NetworkConfig {
    fn from_env() -> Self {
        let host = env::var("SYSLOG_HOST").unwrap_or_else(|_| "logrelay.lookback.io".to_string());
        let port = env::var("SYSLOG_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6514);
        let use_tls = env::var("SYSLOG_TLS")
            .map(|x| x == "1" || x == "true")
            .unwrap_or(false);
        let api_key_id = env::var("SYSLOG_API_KEY_ID").unwrap_or_else(|_| "".into());
        let api_key = env::var("SYSLOG_API_KEY").unwrap_or_else(|_| "".into());

        Self {
            host,
            port,
            api_key,
            api_key_id,
            use_tls,
        }
    }
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
            backend: Some(BackendConfig::default()),
        }
    }
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self::Network(NetworkConfig::from_env())
    }
}

static BACKEND_SINGLETON: Mutex<Option<Backend>> = Mutex::new(None);

/// Logging implementation for tracing crate.
pub struct Logger {
    /// The config of the logging system.
    config: Arc<LogConfig>,
    /// Base record with fields that don't change.
    base_record: Arc<LogRecord>,
    backend: Option<Backend>,
}

impl Logger {
    pub fn init(config: LogConfig) -> Result<(), Error> {
        let config = Arc::new(config);

        let base_record = Arc::new(LogRecord {
            facility: Arc::new(SyslogFacility::Local1),
            hostname: Arc::new(config.hostname.clone()),
            app_name: Arc::new(config.app_name.clone()),
            pid: config.pid,
            env: Arc::new(config.env.clone()),

            severity: SyslogSeverity::Informational,
            msg_id: "".to_string(),
            timestamp: Utc::now(),
            message: None,
            well_known: None,
        });
        let backend = match &config.backend {
            None => None,
            Some(BackendConfig::Network(NetworkConfig {
                host,
                port,
                api_key_id,
                api_key,
                use_tls,
            })) => {
                assert!(use_tls, "TLS must be used");
                let id = if api_key_id.is_empty() {
                    config.app_name.clone()
                } else {
                    api_key_id.clone()
                };

                Some(Backend::network(host.clone(), *port, id, api_key.clone()))
            }
            Some(BackendConfig::System {}) => {
                let backend = Backend::system()?;
                Some(backend)
            }
        };

        if let Some(backend) = &backend {
            let mut lock = BACKEND_SINGLETON.lock().unwrap();
            assert!(
                lock.is_none(),
                "Logger with backend can only be initialized once"
            );

            *lock = Some(backend.clone());
        }

        let logger = Logger {
            config,
            base_record,
            backend,
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

        handle_log_record(record, self.backend.as_ref());
    }
}

#[derive(Debug, Clone)]
struct LogRecord {
    facility: Arc<SyslogFacility>,
    hostname: Arc<String>,
    app_name: Arc<String>,
    pid: u32,
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

/// Send messages to log server
fn handle_log_record(r: LogRecord, backend: Option<&Backend>) {
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
    let send_to_backend = backend.map(|b| b.active()).unwrap_or(false);
    // Don't log telemetry
    let should_log = !r.app_name.ends_with(".telemetry");

    // don't log to console when we are sending to host, this to avoid double logging when
    // deployed in frontloader which also forwards console to the log servers.
    if !send_to_backend && should_log {
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

    if let Some(b) = backend {
        b.log(&r);
    }
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
        let mut lock = BACKEND_SINGLETON.lock().unwrap();
        if let Some(backend) = &mut *lock {
            backend.flush().ok();
        };
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

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Tls(rustls::Error),
    Dns(InvalidDnsNameError),
    NulError(NulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{}", e),
            Error::Tls(e) => write!(f, "{}", e),
            Error::Dns(e) => write!(f, "{}", e),
            Error::NulError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Tls(e) => Some(e),
            Error::Dns(e) => Some(e),
            Error::NulError(e) => Some(e),
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

impl From<NulError> for Error {
    fn from(e: NulError) -> Self {
        Error::NulError(e)
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
