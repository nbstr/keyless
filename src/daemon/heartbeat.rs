use std::os::unix::net::UnixStream;
use std::thread;

use crate::NAME;
use crate::ipc::protocol::{Reply, write_frame};

use super::HEARTBEAT;

/// The connection saying "still here" on the socket every [`HEARTBEAT`], for
/// as long as this is held.
///
/// # Why the guard is the connection thread's, for the life of the request
///
/// The heartbeat once wrapped the lookup alone, because the lookup was the
/// step known to be slow: a vendor CLI and a network round trip. Everything
/// else on the request path ran on the connection thread in silence — and
/// one of those steps is this daemon's own slow one. An audit append takes an
/// exclusive lock on a log every connection thread shares, reads its tail,
/// and writes an anchor through a full `fsync`, so under a busy log or a slow
/// disk the append alone outlasts what the lookup left of the client's
/// deadline. Five degrades on a live install had that shape: the client gave
/// up, and the daemon then recorded `allow` for the same name a few seconds
/// later. A denial and a malformed name write rows on the same lock and were
/// never under the heartbeat at all, so a refused client on a held log read
/// as a wedge rather than a refusal.
///
/// The client's deadline bounds SILENCE, and it cannot know which step it is
/// waiting on. So the guard is taken by the connection thread the moment the
/// request is decoded and dropped only when the reply exists, and coverage is
/// a property of the request path rather than of any step on it: a step added
/// later — another audit row, a catalogue walk — is under the heartbeat
/// without anyone remembering to put it there.
///
/// # Two writers, one socket, and why the bytes never interleave
///
/// While this is held there are two threads that may write to the
/// connection, and the frame writer is whole-frame: the beat thread writes
/// nothing but complete `Working` frames, and the connection thread writes
/// nothing at all until it has dropped this, which joins the beat thread.
/// That join is the handover between the two writers, so the reply frame
/// starts only after the last heartbeat frame has ended.
///
/// # What happens when the client has already gone
///
/// The heartbeat write fails, the beating stops, and the request goes on
/// being answered anyway. The lookup is already paid for; letting it finish
/// records the audit row the request earned and leaves the value in the
/// resolver's cache, so the retry the caller is about to make is answered
/// from memory. Abandoning it would throw away the work and make the next
/// attempt pay for it again — which, on a store that is slow enough to have
/// reached this code, is how a client ends up unable to resolve a name it
/// asks for repeatedly.
pub(super) struct Heartbeat {
    /// Dropped to tell the beat thread to stop; the thread sees it as the
    /// channel disconnecting.
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Heartbeat {
    /// Start beating on `stream`.
    ///
    /// `None` when there is no descriptor or no thread to be had, and the
    /// request is then answered in silence — which is late, and late is
    /// exactly what this daemon did before it could speak.
    pub(super) fn start(stream: &UnixStream) -> Option<Self> {
        let stream = stream.try_clone().ok()?;
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let thread = thread::Builder::new()
            .name(format!("{NAME}d-heartbeat"))
            .spawn(move || {
                let mut heard = true;
                loop {
                    match stopped.recv_timeout(HEARTBEAT) {
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if heard {
                                heard = write_frame(
                                    &mut &stream,
                                    &Reply::Working.encode().unwrap_or_default(),
                                )
                                .is_ok();
                            }
                        }
                        // Nothing is ever sent; the sender dropping is the
                        // only thing this can receive.
                        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .ok()?;
        Some(Heartbeat {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
