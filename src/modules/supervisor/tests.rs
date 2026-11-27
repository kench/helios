//! Supervisor tests, with a scripted module whose runs fail, panic, return or wait in turn.

use std::collections::VecDeque;
use std::sync::Mutex;

use tokio::sync::mpsc;

use super::*;
use crate::modules::{ModuleError, ModuleFuture};

const WAIT: Duration = Duration::from_secs(5);

/// What one run of the scripted module does.
#[derive(Debug, Clone)]
enum Run {
    Fail(&'static str),
    Panic(&'static str),
    Return,
    /// Runs until cancelled.
    Wait,
    /// Runs until cancelled, then fails.
    FailOnStop,
}

struct Scripted {
    runs: Mutex<VecDeque<Run>>,
    started: mpsc::UnboundedSender<Instant>,
}

impl Module for Scripted {
    fn name(&self) -> &'static str {
        "test"
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        let next = self
            .runs
            .lock()
            .map_or(Run::Wait, |mut runs| runs.pop_front().unwrap_or(Run::Wait));
        let _ = self.started.send(Instant::now());
        Box::pin(async move {
            match next {
                Run::Fail(message) => Err(ModuleError(message.to_owned())),
                Run::Panic(message) => panic!("{message}"),
                Run::Return => Ok(()),
                Run::Wait => {
                    ctx.cancel.cancelled().await;
                    Ok(())
                }
                Run::FailOnStop => {
                    ctx.cancel.cancelled().await;
                    Err(ModuleError("couldn't clean up".to_owned()))
                }
            }
        })
    }
}

struct Setup {
    states: watch::Receiver<ModuleStates>,
    tasks: Vec<JoinHandle<()>>,
    started: mpsc::UnboundedReceiver<Instant>,
    registrations: mpsc::UnboundedReceiver<(String, mpsc::Sender<crate::router::PendingCommand>)>,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn fast() -> Timing {
    Timing {
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(40),
        stable_run: Duration::from_secs(3600),
    }
}

fn setup(runs: Vec<Run>, timing: Timing) -> Setup {
    let (router, registrations) = RouterHandle::for_test();
    let (shadows, _reports) = ShadowHandle::for_test();
    let (mqtt, _requests, _status) = MqttHandle::for_test();
    let (started_tx, started) = mpsc::unbounded_channel();
    let module = Scripted {
        runs: Mutex::new(runs.into()),
        started: started_tx,
    };
    let cancel = CancellationToken::new();
    let (states, tasks) = start(
        vec![Arc::new(module)],
        &Deps {
            router,
            shadows,
            mqtt,
            sysfs: PathBuf::from("/sys"),
        },
        timing,
        &cancel,
    );
    Setup {
        states,
        tasks,
        started,
        registrations,
        cancel,
    }
}

/// Waits for the `test` module's status to satisfy `check`.
async fn wait_for(setup: &mut Setup, check: impl Fn(&ModuleStatus) -> bool) -> ModuleStatus {
    let found = tokio::time::timeout(
        WAIT,
        setup
            .states
            .wait_for(|states| states.get("test").is_some_and(&check)),
    )
    .await
    .expect("the module state in time")
    .expect("the supervisor running");
    found["test"].clone()
}

async fn next_start(setup: &mut Setup) -> Instant {
    tokio::time::timeout(WAIT, setup.started.recv())
        .await
        .expect("a run in time")
        .expect("the module")
}

#[tokio::test]
async fn starts_modules_as_running() {
    let mut setup = setup(vec![Run::Wait], fast());

    next_start(&mut setup).await;
    let status = setup.states.borrow()["test"].clone();

    assert_eq!(status.state, RunState::Running);
    assert_eq!(status.restarts, 0);
    assert_eq!(status.last_error, None);
}

#[tokio::test]
async fn restarts_a_failed_module_and_keeps_why() {
    let mut setup = setup(vec![Run::Fail("framebuffer gone"), Run::Wait], fast());

    next_start(&mut setup).await;
    next_start(&mut setup).await;
    let status = wait_for(&mut setup, |s| s.restarts == 1).await;

    assert_eq!(status.state, RunState::Running);
    assert_eq!(status.last_error.as_deref(), Some("framebuffer gone"));
}

#[tokio::test]
async fn restarts_a_module_that_panicked() {
    let mut setup = setup(vec![Run::Panic("bad state"), Run::Wait], fast());

    next_start(&mut setup).await;
    next_start(&mut setup).await;
    let status = wait_for(&mut setup, |s| s.restarts == 1).await;

    assert_eq!(status.last_error.as_deref(), Some("panicked: bad state"));
}

#[tokio::test]
async fn restarts_a_module_that_returned_without_being_cancelled() {
    let mut setup = setup(vec![Run::Return, Run::Wait], fast());

    next_start(&mut setup).await;
    next_start(&mut setup).await;
    let status = wait_for(&mut setup, |s| s.restarts == 1).await;

    assert_eq!(
        status.last_error.as_deref(),
        Some("returned without being asked to stop")
    );
}

#[tokio::test]
async fn reports_restarting_while_waiting_to_restart() {
    let timing = Timing {
        initial_delay: Duration::from_secs(3600),
        max_delay: Duration::from_secs(3600),
        stable_run: Duration::from_secs(3600),
    };
    let mut setup = setup(vec![Run::Fail("boom")], timing);

    let status = wait_for(&mut setup, |s| s.state == RunState::Restarting).await;
    assert_eq!(status.last_error.as_deref(), Some("boom"));
    assert_eq!(status.restarts, 0);

    // Shutdown doesn't wait out the delay.
    setup.cancel.cancel();
    for task in std::mem::take(&mut setup.tasks) {
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    }
    assert_eq!(setup.states.borrow()["test"].state, RunState::Stopped);
}

#[tokio::test]
async fn every_run_registers_its_commands_again() {
    let mut setup = setup(vec![Run::Fail("once"), Run::Wait], fast());

    next_start(&mut setup).await;
    next_start(&mut setup).await;
    for _ in 0..2 {
        let (module, _) = tokio::time::timeout(WAIT, setup.registrations.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(module, "test");
    }
}

#[tokio::test]
async fn stops_when_cancelled_and_waits_for_the_run() {
    let mut setup = setup(vec![Run::Wait], fast());
    next_start(&mut setup).await;

    setup.cancel.cancel();
    for task in std::mem::take(&mut setup.tasks) {
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    }

    let status = setup.states.borrow()["test"].clone();
    assert_eq!(status.state, RunState::Stopped);
    assert_eq!(status.last_error, None);
}

#[tokio::test]
async fn a_long_enough_run_resets_the_backoff() {
    // Every run counts as stable, so each delay starts from the initial 200 ms again. Without
    // the reset, four delays would take at least 100 + 200 + 400 + 800 ms.
    let timing = Timing {
        initial_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(3600),
        stable_run: Duration::ZERO,
    };
    let runs = vec![
        Run::Fail("1"),
        Run::Fail("2"),
        Run::Fail("3"),
        Run::Fail("4"),
        Run::Wait,
    ];
    let mut setup = setup(runs, timing);

    let first = next_start(&mut setup).await;
    let mut last = first;
    for _ in 0..4 {
        last = next_start(&mut setup).await;
    }

    assert!(
        last - first < Duration::from_millis(1200),
        "{:?}",
        last - first
    );
}

#[test]
fn panic_messages_come_from_str_and_string_payloads() {
    assert_eq!(panic_message(&"static"), "static");
    assert_eq!(panic_message(&String::from("owned")), "owned");
    assert_eq!(panic_message(&42_u8), "(no message)");
}

#[tokio::test]
async fn a_module_failing_while_stopping_still_ends_stopped() {
    let mut setup = setup(vec![Run::FailOnStop], fast());
    next_start(&mut setup).await;

    setup.cancel.cancel();
    for task in std::mem::take(&mut setup.tasks) {
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    }

    let status = setup.states.borrow()["test"].clone();
    assert_eq!(status.state, RunState::Stopped);
    assert_eq!(status.restarts, 0);
}

#[test]
fn run_states_have_shadow_names() {
    assert_eq!(RunState::Running.as_str(), "running");
    assert_eq!(RunState::Restarting.as_str(), "restarting");
    assert_eq!(RunState::Stopped.as_str(), "stopped");
}
