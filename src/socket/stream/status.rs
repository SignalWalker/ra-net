use std::{future::Future, sync::Arc, time::Duration};

use parking_lot::{Condvar, Mutex};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendState {
    #[default]
    Pending,
    Lost,
    Acknowledged,
}

#[derive(Debug, Clone)]
pub struct SendStatus {
    state: Arc<(Mutex<SendState>, Condvar)>,
}

impl SendStatus {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(SendState::Pending), Condvar::new())),
        }
    }

    pub(super) fn trip(&self, state: SendState) {
        let &(ref lock, ref cvar) = &*self.state;
        let mut status = lock.lock();
        *status = state;
        cvar.notify_all();
    }

    pub fn status(&self) -> SendState {
        *self.state.0.lock()
    }

    pub fn wait(&self) -> SendState {
        let &(ref lock, ref cvar) = &*self.state;
        let mut status = lock.lock();
        if *status != SendState::Pending {
            return *status;
        }
        cvar.wait(&mut status);
        *status
    }

    pub fn wait_for(&self, dur: Duration) -> Result<SendState, parking_lot::WaitTimeoutResult> {
        let &(ref lock, ref cvar) = &*self.state;
        let mut status = lock.lock();
        if *status != SendState::Pending {
            return Ok(*status);
        }
        let wait_res = cvar.wait_for(&mut status, dur);
        match *status {
            SendState::Pending => Err(wait_res),
            _ => Ok(*status),
        }
    }
}

impl Future for SendStatus {
    type Output = SendState;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;
        let state = self.status();
        match state {
            SendState::Pending => Poll::Pending,
            _ => Poll::Ready(state),
        }
    }
}
