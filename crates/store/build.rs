// `sqlx::migrate!` embeds migrations at compile time -> rebuild on added or changed migration.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
