//! CRDT Last-Write-Wins (LWW) per-column merge logic.
//!
//! Port of the core reconciliation from `packages/common/src/local-first/Sync.ts`.

use crate::timestamp::order_timestamp_bytes;
use crate::types::*;
use core::cmp::Ordering;

/// A database change (one mutation to a row).
///
/// Each change targets a single row in a table and contains column-value
/// pairs. System columns (createdAt, updatedAt, isDeleted) are derived
/// from the change metadata, not stored in `values`.
#[derive(Clone, Debug, PartialEq)]
pub struct DbChange<'a> {
    /// Table name.
    pub table: &'a str,
    /// Row identifier (16 bytes).
    pub id: IdBytes,
    /// Column-value pairs (excluding system columns).
    pub values: &'a [(&'a str, SqliteValue<'a>)],
    /// True if this is the first write to this row (sets createdAt).
    pub is_insert: bool,
    /// None = not a delete operation. Some(true) = soft delete. Some(false) = undelete.
    pub is_delete: Option<bool>,
}

/// SqliteValue for column data.
///
/// Represents the possible value types stored in Evolu columns.
/// Uses borrowed data from the page buffer to avoid allocation.
#[derive(Clone, Debug, PartialEq)]
pub enum SqliteValue<'a> {
    Null,
    Integer(i64),
    Float(f64),
    Text(&'a str),
    Blob(&'a [u8]),
}

/// System columns automatically managed by Evolu.
pub const SYSTEM_COLUMNS: &[&str] = &["createdAt", "updatedAt", "isDeleted", "ownerId"];

/// System columns including "id".
pub const SYSTEM_COLUMNS_WITH_ID: &[&str] = &["id", "createdAt", "updatedAt", "isDeleted", "ownerId"];

/// Determine whether a column change should be applied based on LWW semantics.
///
/// Returns true if `incoming_timestamp` is strictly newer than `existing_timestamp`.
/// If no existing timestamp, the change always applies.
///
/// This mirrors the SQL logic in `applyColumnChange` (Sync.ts:800-842):
/// ```sql
/// WHERE NOT EXISTS (SELECT 1 FROM evolu_history
///   WHERE ... AND timestamp >= incoming_timestamp)
/// ```
pub fn should_apply_column(
    existing_timestamp: Option<&TimestampBytes>,
    incoming_timestamp: &TimestampBytes,
) -> bool {
    match existing_timestamp {
        None => true,
        Some(existing) => {
            // Apply only if incoming is strictly newer (existing < incoming).
            // The TS code rejects if existing >= incoming.
            order_timestamp_bytes(existing, incoming_timestamp) == Ordering::Less
        }
    }
}

/// Convert a DbChange into the set of columns that need to be written.
///
/// Returns an iterator over (column_name, is_system) pairs.
/// System columns are: createdAt/updatedAt (based on is_insert) and isDeleted.
pub fn change_columns<'a>(change: &'a DbChange<'a>) -> ChangeColumns<'a> {
    ChangeColumns {
        change,
        user_index: 0,
        system_phase: SystemPhase::DateTime,
    }
}

/// Iterator over columns in a DbChange (user values + system columns).
pub struct ChangeColumns<'a> {
    change: &'a DbChange<'a>,
    user_index: usize,
    system_phase: SystemPhase,
}

#[derive(Clone, Copy)]
enum SystemPhase {
    DateTime,
    IsDeleted,
    Done,
}

impl<'a> Iterator for ChangeColumns<'a> {
    /// (column_name, is_system_column)
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // First yield system columns
        match self.system_phase {
            SystemPhase::DateTime => {
                self.system_phase = SystemPhase::IsDeleted;
                if self.change.is_insert {
                    return Some("createdAt");
                } else {
                    return Some("updatedAt");
                }
            }
            SystemPhase::IsDeleted => {
                self.system_phase = SystemPhase::Done;
                if self.change.is_delete.is_some() {
                    return Some("isDeleted");
                }
                // Fall through to user columns
            }
            SystemPhase::Done => {}
        }

        // Then yield user value columns
        if self.user_index < self.change.values.len() {
            let (col, _) = &self.change.values[self.user_index];
            self.user_index += 1;
            Some(col)
        } else {
            None
        }
    }
}

/// Check if a column name is a system column (should not appear in user values).
pub fn is_system_column(name: &str) -> bool {
    SYSTEM_COLUMNS_WITH_ID.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_apply_no_existing() {
        let ts = [0u8; 16];
        assert!(should_apply_column(None, &ts));
    }

    #[test]
    fn should_apply_newer_wins() {
        let older = [0u8; 16];
        let newer = {
            let mut ts = [0u8; 16];
            ts[5] = 1; // millis = 1
            ts
        };

        assert!(should_apply_column(Some(&older), &newer));
        assert!(!should_apply_column(Some(&newer), &older));
        assert!(!should_apply_column(Some(&older), &older)); // equal = reject
    }

    #[test]
    fn change_columns_insert() {
        let change = DbChange {
            table: "todo",
            id: IdBytes([0; 16]),
            values: &[("title", SqliteValue::Text("Buy milk"))],
            is_insert: true,
            is_delete: None,
        };

        let cols: Vec<&str> = change_columns(&change).collect();
        assert_eq!(cols, vec!["createdAt", "title"]);
    }

    #[test]
    fn change_columns_update() {
        let change = DbChange {
            table: "todo",
            id: IdBytes([0; 16]),
            values: &[("title", SqliteValue::Text("Updated"))],
            is_insert: false,
            is_delete: None,
        };

        let cols: Vec<&str> = change_columns(&change).collect();
        assert_eq!(cols, vec!["updatedAt", "title"]);
    }

    #[test]
    fn change_columns_delete() {
        let change = DbChange {
            table: "todo",
            id: IdBytes([0; 16]),
            values: &[],
            is_insert: false,
            is_delete: Some(true),
        };

        let cols: Vec<&str> = change_columns(&change).collect();
        assert_eq!(cols, vec!["updatedAt", "isDeleted"]);
    }

    #[test]
    fn system_column_detection() {
        assert!(is_system_column("id"));
        assert!(is_system_column("createdAt"));
        assert!(is_system_column("updatedAt"));
        assert!(is_system_column("isDeleted"));
        assert!(is_system_column("ownerId"));
        assert!(!is_system_column("title"));
        assert!(!is_system_column("name"));
    }
}
