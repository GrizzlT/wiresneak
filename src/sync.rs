use std::{ops::{Deref, DerefMut}, sync::{Arc, atomic::{AtomicBool, Ordering}}};

use tokio_stream::Stream;
use tokio::sync::mpsc;

pub struct GatedSender<T> {
    tx: mpsc::Sender<T>,
    enabled: Arc<AtomicBool>,
}

pub struct GatedReceiver<T> {
    inner: mpsc::Receiver<T>,
    enabled: Arc<AtomicBool>,
}

pub fn gated_channel<T>(buffer: usize) -> (GatedSender<T>, GatedReceiver<T>) {
    let (tx, rx) = mpsc::channel(buffer);
    let enabled = Arc::new(AtomicBool::new(false));
    (
        GatedSender { tx, enabled: enabled.clone(), },
        GatedReceiver { inner: rx, enabled }
    )
}

impl<T> GatedSender<T> {
    pub async fn guard<F, O>(&self, f: F) -> Option<O>
    where
        F: AsyncFnOnce(&mpsc::Sender<T>) -> O,
    {
        if self.enabled.load(Ordering::Relaxed) {
            Some(f(&self.tx).await)
        } else {
            None
        }
    }

    pub fn inner(&self) -> &mpsc::Sender<T> {
        &self.tx
    }
}

impl<T> GatedReceiver<T> {
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn pause_and_drain(&mut self) {
        self.set_enabled(false);
        while self.inner.try_recv().is_ok() {}
    }
}

impl<T> Deref for GatedReceiver<T> {
    type Target = mpsc::Receiver<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for GatedReceiver<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> Stream for GatedReceiver<T> {
    type Item = T;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.inner.is_closed() {
            let used_capacity = self.inner.max_capacity() - self.inner.capacity();
            (self.inner.len(), Some(used_capacity))
        } else {
            (self.inner.len(), None)
        }
    }
}
