//! This module contains lower-level primitives for visiting fields.

use std::fmt;

use serde_json::map::Map;
use serde_json::Value;
use tracing_core::field::{Field, Visit};

/// The visitor necessary to record values in GELF format.
#[derive(Debug)]
pub struct AdditionalFieldVisitor<'a> {
    object: &'a mut Map<String, Value>,
}

impl<'a> AdditionalFieldVisitor<'a> {
    /// Create a new [`AdditionalFieldVisitor`] from a [`Map`].
    pub fn new(object: &'a mut Map<String, Value>) -> Self {
        AdditionalFieldVisitor { object }
    }

    fn record_additional_value<V: Into<Value>>(&mut self, field: &str, value: V) {
        let new_key = field.to_string();
        self.object.insert(new_key, value.into());
    }
}

impl<'a> Visit for AdditionalFieldVisitor<'a> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{:?}", value);
        let field_name = field.name();
        self.record_additional_value(field_name, value)
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        let field_name = field.name();
        self.record_additional_value(field_name, value)
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        let field_name = field.name();
        self.record_additional_value(field_name, value)
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        let field_name = field.name();
        self.record_additional_value(field_name, value)
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let field_name = field.name();
        self.record_additional_value(field_name, value)
    }
}
