//! Applied migrations never change: checksum differs -> sqlx refuses to start.
//! `MIGRATIONS.sum` freezes them. New migration -> add a line (the test prints it).
//! Never edit an existing file, not even a comment.
#![allow(clippy::unwrap_used)]

#[test]
fn applied_migrations_are_unchanged() {
    let frozen = include_str!("../migrations/MIGRATIONS.sum");
    let migrator = sqlx::migrate!("./migrations");
    let mut missing = Vec::new();
    for m in migrator.iter() {
        let sum: String = m.checksum.iter().map(|b| format!("{b:02x}")).collect();
        let line = format!("{} {sum}", m.version);
        match frozen
            .lines()
            .find(|l| l.starts_with(&format!("{} ", m.version)))
        {
            Some(l) => assert_eq!(
                l, line,
                "migration {} ({}) changed after it was frozen; restore it and add a new migration instead",
                m.version, m.description
            ),
            None => missing.push(line),
        }
    }
    assert!(
        missing.is_empty(),
        "new migrations: append to crates/store/migrations/MIGRATIONS.sum:\n{}",
        missing.join("\n")
    );
}
