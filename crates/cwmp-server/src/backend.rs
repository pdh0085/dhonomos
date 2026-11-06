//! Interface: ACS listener -> business logic (registry, task queue).

use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;

use dhonomos_cwmp_codec::{Fault, Inform, Rpc};
use dhonomos_cwmp_session::Completed;

#[derive(Debug, Clone, Copy)]
pub struct InformContext<'a> {
    pub inform: &'a Inform,
    /// CWMP version from 1.4 negotiation, if any.
    pub cwmp_version: Option<&'a str>,
    pub remote: SocketAddr,
    /// Authenticated username. `None` -> auth off.
    pub username: Option<&'a str>,
    /// [`PasswordCandidate::tag`] of the password the CPE logged in with. 0 = auth off.
    pub credential: u32,
}

/// One password a CPE username may log in with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCandidate {
    pub password: String,
    /// Backend's own ID of this password -> back in [`InformContext::credential`] on login
    /// with it.
    pub tag: u32,
}

/// Business logic behind the ACS. All methods called from request handlers.
/// Error that should make the CPE retry -> return fault 8005.
pub trait Backend: Send + Sync + 'static {
    /// Device handle (e.g. DB ID).
    type Device: Clone + Eq + Hash + Send + Sync + std::fmt::Debug + 'static;
    /// Handle of a dequeued task.
    type Task: Send + Sync + std::fmt::Debug + 'static;

    /// Password for a CPE username. `None` -> CPE rejected.
    fn password(&self, username: &str) -> impl Future<Output = Option<String>> + Send;

    /// All passwords a CPE username may log in with (e.g. new credential in rollout + current).
    /// CPE accepted if it proves any. Default: [`Backend::password`] only.
    fn candidates(&self, username: &str) -> impl Future<Output = Vec<PasswordCandidate>> + Send {
        async move {
            self.password(username)
                .await
                .map(|password| PasswordCandidate { password, tag: 0 })
                .into_iter()
                .collect()
        }
    }

    /// Register or refresh the device from an Inform.
    fn inform(
        &self,
        ctx: InformContext<'_>,
    ) -> impl Future<Output = Result<Self::Device, Fault>> + Send;

    /// CPE request after the Inform (TransferComplete, RequestDownload, ...).
    fn cpe_request(
        &self,
        device: &Self::Device,
        rpc: &Rpc,
    ) -> impl Future<Output = Result<(), Fault>> + Send;

    /// Next request of the ACS turn. `None` -> end the session.
    fn next_request(
        &self,
        device: &Self::Device,
    ) -> impl Future<Output = Option<(Self::Task, Rpc)>> + Send;

    /// Result of a request from [`Backend::next_request`].
    fn completed(
        &self,
        device: &Self::Device,
        task: Self::Task,
        completed: Completed,
    ) -> impl Future<Output = ()> + Send;

    /// Session end. `aborted` = timeout, protocol error or replacement
    /// -> unfinished task must go back to the queue.
    fn session_ended(
        &self,
        device: &Self::Device,
        task: Option<Self::Task>,
        aborted: bool,
    ) -> impl Future<Output = ()> + Send;
}
