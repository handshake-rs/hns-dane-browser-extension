use clap::Parser;
use eframe::egui;
use hns_browser_setup::{
    Browser, BrowserSelection, CANONICAL_EXTENSION_ID, InstallRequest, InstallationStatus,
    Installer, NativePayload, OperationReport, SetupError, VERSION, validate_extension_id,
};
use std::collections::BTreeSet;
use std::error::Error;
#[cfg(not(feature = "embedded-host"))]
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
#[cfg(target_os = "windows")]
use winit::application::ApplicationHandler;
#[cfg(target_os = "windows")]
use winit::dpi::LogicalSize;
#[cfg(target_os = "windows")]
use winit::event::WindowEvent;
#[cfg(target_os = "windows")]
use winit::event_loop::{ActiveEventLoop, EventLoop};
#[cfg(target_os = "windows")]
use winit::window::{Window, WindowId};

const PRODUCT_NAME: &str = "HNS DANE Browser Setup";
const SOURCE_URL: &str = "https://github.com/handshake-rs/hns-dane-browser-extension";
const LICENSE_URL: &str =
    "https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/LICENSE";
const PRIVACY_URL: &str =
    "https://github.com/handshake-rs/hns-dane-browser-extension/blob/main/docs/privacy-policy.md";
const RELEASES_URL: &str = "https://github.com/handshake-rs/hns-dane-browser-extension/releases";
const SPONSORS_URL: &str = "https://github.com/sponsors/denuoweb";
const DONATE_HNS_URL: &str = concat!(
    "handshake:hs1q5997733eq7f4yyk2vq2z8gz3yqyvpz422ypggh",
    "?label=Denuo%20Web%20Handshake%20Browser&message=Handshake%20Browser%20donation"
);

#[derive(Debug, Parser)]
#[command(
    name = "hns-dane-browser-setup",
    version,
    about = "Install, inspect, or completely remove the HNS DANE Browser native components"
)]
struct Arguments {
    /// Install or repair the native host and per-user trust material.
    #[arg(
        long,
        conflicts_with_all = ["uninstall", "status"],
        requires = "extension_ids"
    )]
    install: bool,

    /// Completely remove the native host, registrations, and per-user trust material.
    #[arg(long, conflicts_with_all = ["install", "status"])]
    uninstall: bool,

    /// Print the current installation status as JSON.
    #[arg(long, conflicts_with_all = ["install", "uninstall"])]
    status: bool,

    /// Open and close a real native window after its first redraw for release smoke testing.
    #[arg(
        long,
        conflicts_with_all = ["install", "uninstall", "status"],
        hide = true
    )]
    gui_smoke_test: bool,

    /// Exact 32-character Chromium extension ID. May be repeated.
    #[arg(
        long = "extension-id",
        value_name = "ID",
        action = clap::ArgAction::Append,
        requires = "install"
    )]
    extension_ids: Vec<String>,

    /// Browser registration to install. May be repeated.
    #[arg(
        long = "browser",
        value_name = "BROWSER",
        value_parser = parse_browser,
        action = clap::ArgAction::Append,
        requires = "install",
        help = "Browser registration to install: chrome, chromium, edge, brave, vivaldi, or opera. May be repeated"
    )]
    browsers: Vec<Browser>,

    /// Use this native-host executable instead of the version-matched embedded payload.
    #[cfg(not(feature = "embedded-host"))]
    #[arg(long, value_name = "PATH", requires = "install")]
    native_host: Option<PathBuf>,
}

fn parse_browser(value: &str) -> Result<Browser, String> {
    value.parse()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();

    if arguments.gui_smoke_test {
        #[cfg(target_os = "windows")]
        run_windows_gui_smoke()?;
        #[cfg(not(target_os = "windows"))]
        run_gui(true)?;
    } else if arguments.install || arguments.uninstall || arguments.status {
        run_automation(arguments)?;
    } else {
        run_gui(false)?;
    }

    Ok(())
}

fn run_automation(arguments: Arguments) -> Result<(), SetupError> {
    #[cfg(feature = "embedded-host")]
    let payload = NativePayload::release_embedded();
    #[cfg(not(feature = "embedded-host"))]
    let payload = arguments
        .native_host
        .map(NativePayload::external)
        .unwrap_or_else(NativePayload::release_embedded);
    let installer = Installer::new(payload);

    if arguments.install {
        let extension_ids = arguments.extension_ids;
        for extension_id in &extension_ids {
            validate_extension_id(extension_id)?;
        }

        let browsers = if arguments.browsers.is_empty() {
            BrowserSelection::detected_defaults().selected
        } else {
            arguments.browsers.into_iter().collect()
        };
        if browsers.is_empty() {
            return Err(SetupError::NoBrowsers);
        }

        let report = installer.install(InstallRequest {
            extension_ids,
            browsers,
        })?;
        print_report(&report)?;
    } else if arguments.uninstall {
        let report = installer.uninstall()?;
        print_report(&report)?;
    } else {
        let status = installer.inspect()?;
        println!("{}", serde_json::to_string_pretty(&status)?);
    }

    Ok(())
}

fn print_report(report: &OperationReport) -> Result<(), serde_json::Error> {
    let output = serde_json::json!({
        "summary": &report.summary,
        "details": &report.details,
        "status": &report.status,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn run_gui(close_after_first_frame: bool) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(PRODUCT_NAME)
            .with_inner_size([780.0, 820.0])
            .with_min_inner_size([640.0, 620.0]),
        centered: true,
        ..Default::default()
    };

    eframe::run_native(
        PRODUCT_NAME,
        options,
        Box::new(move |creation_context| {
            Ok(Box::new(SetupApp::new(
                creation_context,
                close_after_first_frame,
            )))
        }),
    )
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct WindowsSmokeApp {
    window: Option<Window>,
    redrawn: bool,
    error: Option<String>,
}

#[cfg(target_os = "windows")]
impl ApplicationHandler for WindowsSmokeApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() || self.error.is_some() {
            return;
        }

        let attributes = Window::default_attributes()
            .with_title(PRODUCT_NAME)
            .with_inner_size(LogicalSize::new(480.0, 320.0))
            .with_visible(true);
        match event_loop.create_window(attributes) {
            Ok(window) => {
                window.request_redraw();
                self.window = Some(window);
            }
            Err(error) => {
                self.error = Some(format!(
                    "unable to create the Windows smoke-test window: {error}"
                ));
                event_loop.exit();
            }
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        if self.window.as_ref().map(|window| window.id()) != Some(window_id) {
            return;
        }

        match event {
            WindowEvent::RedrawRequested => {
                self.redrawn = true;
                event_loop.exit();
            }
            WindowEvent::CloseRequested | WindowEvent::Destroyed => {
                self.error =
                    Some("the Windows smoke-test window closed before its first redraw".to_owned());
                event_loop.exit();
            }
            _ => {}
        }
    }
}

#[cfg(target_os = "windows")]
fn run_windows_gui_smoke() -> Result<(), Box<dyn Error>> {
    let event_loop = EventLoop::new()?;
    let mut application = WindowsSmokeApp::default();
    event_loop.run_app(&mut application)?;

    if let Some(error) = application.error {
        return Err(std::io::Error::other(error).into());
    }
    if !application.redrawn {
        return Err(std::io::Error::other(
            "the Windows smoke-test event loop exited before its first redraw",
        )
        .into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    Inspect,
    Install,
    Uninstall,
}

impl Operation {
    const fn mutates_installation(self) -> bool {
        matches!(self, Self::Install | Self::Uninstall)
    }

    const fn progress_label(self) -> &'static str {
        match self {
            Self::Inspect => "Checking installation status…",
            Self::Install => "Installing or repairing components…",
            Self::Uninstall => "Removing all installed components…",
        }
    }

    const fn log_label(self) -> &'static str {
        match self {
            Self::Inspect => "Checking installation status.",
            Self::Install => "Install or repair started.",
            Self::Uninstall => "Complete uninstall started.",
        }
    }
}

enum WorkerTask {
    Inspect,
    Install(InstallRequest),
    Uninstall,
}

impl WorkerTask {
    const fn operation(&self) -> Operation {
        match self {
            Self::Inspect => Operation::Inspect,
            Self::Install(_) => Operation::Install,
            Self::Uninstall => Operation::Uninstall,
        }
    }
}

enum WorkerOutcome {
    Status(InstallationStatus),
    Report(OperationReport),
}

struct WorkerMessage {
    operation: Operation,
    result: Result<WorkerOutcome, String>,
}

struct SetupApp {
    installer: Installer,
    detected: BTreeSet<Browser>,
    selected: BTreeSet<Browser>,
    extension_ids: String,
    status: Option<InstallationStatus>,
    busy: Option<Operation>,
    confirm_uninstall: bool,
    focus_uninstall_cancel: bool,
    last_error: Option<String>,
    log: Vec<String>,
    worker_tx: Sender<WorkerMessage>,
    worker_rx: Receiver<WorkerMessage>,
    smoke_frames_remaining: Option<u8>,
}

impl SetupApp {
    fn new(creation_context: &eframe::CreationContext<'_>, close_after_first_frame: bool) -> Self {
        let selection = BrowserSelection::detected_defaults();
        let (worker_tx, worker_rx) = mpsc::channel();
        let mut app = Self {
            installer: Installer::new(NativePayload::release_embedded()),
            detected: selection.detected,
            selected: selection.selected,
            extension_ids: String::new(),
            status: None,
            busy: None,
            confirm_uninstall: false,
            focus_uninstall_cancel: false,
            last_error: None,
            log: Vec::new(),
            worker_tx,
            worker_rx,
            smoke_frames_remaining: close_after_first_frame.then_some(1),
        };
        app.start(WorkerTask::Inspect, creation_context.egui_ctx.clone());
        app
    }

    fn start(&mut self, task: WorkerTask, context: egui::Context) {
        if self.busy.is_some() {
            return;
        }

        let operation = task.operation();
        self.busy = Some(operation);
        self.last_error = None;
        self.log.push(operation.log_label().to_owned());

        let installer = self.installer.clone();
        let worker_tx = self.worker_tx.clone();
        thread::spawn(move || {
            let result = match task {
                WorkerTask::Inspect => installer
                    .inspect()
                    .map(WorkerOutcome::Status)
                    .map_err(|error| error.to_string()),
                WorkerTask::Install(request) => installer
                    .install(request)
                    .map(WorkerOutcome::Report)
                    .map_err(|error| error.to_string()),
                WorkerTask::Uninstall => installer
                    .uninstall()
                    .map(WorkerOutcome::Report)
                    .map_err(|error| error.to_string()),
            };
            let _ = worker_tx.send(WorkerMessage { operation, result });
            context.request_repaint();
        });
    }

    fn receive_worker_messages(&mut self) {
        while let Ok(message) = self.worker_rx.try_recv() {
            self.busy = None;
            match message.result {
                Ok(WorkerOutcome::Status(status)) => {
                    self.status = Some(status);
                    self.log.push("Installation status updated.".to_owned());
                }
                Ok(WorkerOutcome::Report(report)) => {
                    self.log.push(report.summary.clone());
                    self.log.extend(report.details.iter().cloned());
                    self.status = Some(report.status);
                }
                Err(error) => {
                    self.last_error = Some(error.clone());
                    self.log.push(format!(
                        "{} failed: {error}",
                        match message.operation {
                            Operation::Inspect => "Status check",
                            Operation::Install => "Install or repair",
                            Operation::Uninstall => "Complete uninstall",
                        }
                    ));
                }
            }
        }
    }

    fn show_status(&self, ui: &mut egui::Ui) {
        ui.heading("Current installation");
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            if let Some(status) = &self.status {
                egui::Grid::new("installation_status")
                    .num_columns(2)
                    .spacing([18.0, 7.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Complete installation");
                        ui.label(if status.installed {
                            "Installed"
                        } else {
                            "Not installed"
                        });
                        ui.end_row();

                        ui.strong("Installed version");
                        match &status.version {
                            Some(version) if version == VERSION => {
                                ui.label(format!("{version} (matches setup)"));
                            }
                            Some(version) => {
                                ui.colored_label(
                                    egui::Color32::YELLOW,
                                    format!("{version} (setup is {VERSION}; repair recommended)"),
                                );
                            }
                            None if status.installed => {
                                ui.label("Not reported");
                            }
                            None => {
                                ui.label("Not installed");
                            }
                        }
                        ui.end_row();

                        ui.strong("Per-user CA");
                        ui.label(if status.ca_installed {
                            "Installed"
                        } else {
                            "Not installed"
                        });
                        ui.end_row();

                        ui.strong("Registered extension IDs");
                        ui.label(if status.extension_ids.is_empty() {
                            "None".to_owned()
                        } else {
                            status.extension_ids.join("\n")
                        });
                        ui.end_row();

                        ui.strong("Registered browsers");
                        ui.label(if status.browsers.is_empty() {
                            "None".to_owned()
                        } else {
                            status
                                .browsers
                                .iter()
                                .map(|browser| browser.label())
                                .collect::<Vec<_>>()
                                .join(", ")
                        });
                        ui.end_row();

                        ui.strong("Native host path");
                        ui.label(
                            status.native_host_path.as_ref().map_or_else(
                                || "None".to_owned(),
                                |path| path.display().to_string(),
                            ),
                        );
                        ui.end_row();
                    });
            } else {
                ui.label("Status is unavailable. See the activity log for details.");
            }
        });
    }

    fn show_configuration(&mut self, ui: &mut egui::Ui) {
        ui.heading("Extensions");
        ui.label(
            "On the extension's first-run page, copy the exact 32-character extension ID and \
             paste it here. Separate multiple IDs with a newline, comma, or space. Browser \
             catalogs can assign different IDs.",
        );
        ui.add_enabled(
            self.busy.is_none(),
            egui::TextEdit::multiline(&mut self.extension_ids)
                .desired_width(f32::INFINITY)
                .desired_rows(2)
                .hint_text("One or more exact extension IDs"),
        );
        if ui
            .add_enabled(
                self.busy.is_none(),
                egui::Button::new("Use canonical GitHub / unpacked extension ID"),
            )
            .on_hover_text(CANONICAL_EXTENSION_ID)
            .clicked()
        {
            self.extension_ids = CANONICAL_EXTENSION_ID.to_owned();
        }
        ui.small(format!(
            "Canonical GitHub / unpacked ID (informational): {CANONICAL_EXTENSION_ID}"
        ));
        if self.extension_ids.trim().is_empty() {
            ui.label("Paste at least one extension ID to enable Install or Repair.");
        } else if self.entered_extension_ids().is_none() {
            ui.colored_label(
                egui::Color32::RED,
                "Every ID must be exactly 32 lowercase letters in the range a–p.",
            );
        }

        ui.add_space(8.0);
        ui.heading("Browsers");
        ui.label(
            "Detected browsers are selected by default. If none can be detected, all six are \
             selected for you to review. You can change every selection.",
        );
        ui.add_enabled_ui(self.busy.is_none(), |ui| {
            for browser in Browser::ALL {
                let mut selected = self.selected.contains(&browser);
                let detection = if self.detected.contains(&browser) {
                    "detected"
                } else {
                    "not detected"
                };
                if ui
                    .checkbox(
                        &mut selected,
                        format!("{}  —  {detection}", browser.label()),
                    )
                    .changed()
                {
                    if selected {
                        self.selected.insert(browser);
                    } else {
                        self.selected.remove(&browser);
                    }
                }
            }
        });
        if self.selected.is_empty() {
            ui.colored_label(
                egui::Color32::RED,
                "Select at least one browser before installing or repairing.",
            );
        }
    }

    fn show_actions(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            ui.colored_label(
                egui::Color32::YELLOW,
                "Close the selected browsers before Install or Repair. Close all supported \
                 browsers before Complete Uninstall, then restart them when setup finishes.",
            );
        });

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let install_enabled = self.busy.is_none()
                && !self.selected.is_empty()
                && self.entered_extension_ids().is_some();
            if ui
                .add_enabled(
                    install_enabled,
                    egui::Button::new("Install or Repair").min_size([150.0, 32.0].into()),
                )
                .clicked()
            {
                self.start(
                    WorkerTask::Install(InstallRequest {
                        extension_ids: self
                            .entered_extension_ids()
                            .expect("validated extension IDs"),
                        browsers: self.selected.clone(),
                    }),
                    ui.ctx().clone(),
                );
            }

            if ui
                .add_enabled(
                    self.busy.is_none(),
                    egui::Button::new("Complete Uninstall").min_size([160.0, 32.0].into()),
                )
                .clicked()
            {
                self.confirm_uninstall = true;
                self.focus_uninstall_cancel = true;
            }

            if ui
                .add_enabled(
                    self.busy.is_none(),
                    egui::Button::new("Refresh Status").min_size([125.0, 32.0].into()),
                )
                .clicked()
            {
                self.start(WorkerTask::Inspect, ui.ctx().clone());
            }
        });
    }

    fn show_uninstall_confirmation(&mut self, context: &egui::Context) {
        if !self.confirm_uninstall {
            return;
        }

        let request_cancel_focus = self.focus_uninstall_cancel;
        let mut cancel = false;
        let mut confirm = false;
        let modal =
            egui::Modal::new(egui::Id::new("confirm_complete_uninstall")).show(context, |ui| {
                ui.set_max_width(520.0);
                ui.heading("Completely uninstall HNS DANE Browser components?");
                ui.label(
                    "Close all supported browsers first. This removes the following per-user \
                     components owned by this setup:",
                );
                ui.add_space(4.0);
                ui.label(
                    "• Native Messaging host registrations for Google Chrome, Chromium, \
                     Microsoft Edge, Brave, Vivaldi, and Opera.",
                );
                ui.label("• The installed native host and its per-user runtime/setup files.");
                ui.label(
                    "• The HNS DANE per-user CA certificate, private key, and supported browser \
                     trust entries.",
                );
                ui.add_space(4.0);
                ui.strong(
                    "Browser extensions, profiles, bookmarks, and other browser data remain.",
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let cancel_response = ui.add(
                        egui::Button::new(egui::RichText::new("Cancel").strong())
                            .min_size([110.0, 30.0].into()),
                    );
                    if request_cancel_focus {
                        cancel_response.request_focus();
                    }
                    cancel |= cancel_response.clicked();

                    let warning_color = ui.visuals().error_fg_color;
                    confirm |= ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("Yes, completely uninstall")
                                    .color(warning_color),
                            )
                            .min_size([190.0, 30.0].into()),
                        )
                        .clicked();
                });
            });
        self.focus_uninstall_cancel = false;

        if confirm {
            self.confirm_uninstall = false;
            self.start(WorkerTask::Uninstall, context.clone());
        } else if cancel || modal.should_close() {
            self.confirm_uninstall = false;
        }
    }

    fn show_activity(&self, ui: &mut egui::Ui) {
        ui.heading("Progress and activity");
        if let Some(operation) = self.busy {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(operation.progress_label());
            });
            if operation.mutates_installation() {
                ui.small(
                    "Setup must remain open until this operation finishes; window close is \
                     temporarily disabled.",
                );
            }
        } else {
            ui.label("Ready.");
        }

        if let Some(error) = &self.last_error {
            ui.colored_label(egui::Color32::RED, error);
        }

        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt("activity_log")
                .max_height(150.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.label(egui::RichText::new(line).monospace().small());
                    }
                });
        });
    }

    fn entered_extension_ids(&self) -> Option<Vec<String>> {
        let extension_ids: Vec<_> = self
            .extension_ids
            .split(|character: char| character.is_whitespace() || character == ',')
            .filter(|extension_id| !extension_id.is_empty())
            .map(str::to_owned)
            .collect();
        (!extension_ids.is_empty()
            && extension_ids
                .iter()
                .all(|extension_id| validate_extension_id(extension_id).is_ok()))
        .then_some(extension_ids)
    }

    fn show_links(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.hyperlink_to("Source", SOURCE_URL);
            ui.separator();
            ui.hyperlink_to("License", LICENSE_URL);
            ui.separator();
            ui.hyperlink_to("Privacy", PRIVACY_URL);
            ui.separator();
            ui.hyperlink_to("Releases", RELEASES_URL);
            ui.separator();
            ui.label(format!("Setup {VERSION}"));
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Donations are optional and unlock no features:");
            ui.hyperlink_to("GitHub Sponsors", SPONSORS_URL);
            ui.separator();
            ui.hyperlink_to("Donate HNS", DONATE_HNS_URL);
        });
    }
}

impl eframe::App for SetupApp {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive_worker_messages();
        if self.busy.is_some_and(Operation::mutates_installation)
            && context.input(|input| input.viewport().close_requested())
        {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.heading(PRODUCT_NAME);
                    ui.label(
                        "Install the version-matched native host and per-user CA for supported \
                         Chromium browsers.",
                    );
                    ui.add_space(10.0);

                    self.show_status(ui);
                    ui.separator();
                    self.show_configuration(ui);
                    ui.separator();
                    self.show_actions(ui);
                    ui.separator();
                    self.show_activity(ui);
                    ui.separator();
                    self.show_links(ui);
                });
        });
        self.show_uninstall_confirmation(ui.ctx());
        if let Some(frames_remaining) = self.smoke_frames_remaining {
            if frames_remaining == 0 {
                self.smoke_frames_remaining = None;
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            } else {
                self.smoke_frames_remaining = Some(frames_remaining - 1);
                ui.ctx().request_repaint();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mutation_workers_block_window_close() {
        assert!(!Operation::Inspect.mutates_installation());
        assert!(Operation::Install.mutates_installation());
        assert!(Operation::Uninstall.mutates_installation());
    }

    #[cfg(feature = "embedded-host")]
    #[test]
    fn embedded_release_cli_rejects_native_host_override() {
        let error = Arguments::try_parse_from([
            "hns-dane-browser-setup",
            "--install",
            "--extension-id",
            CANONICAL_EXTENSION_ID,
            "--native-host",
            "untrusted-host",
        ])
        .expect_err("embedded release CLI must reject native-host overrides");

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn gui_smoke_test_is_an_isolated_cli_mode() {
        let arguments = Arguments::try_parse_from(["hns-dane-browser-setup", "--gui-smoke-test"])
            .expect("the release GUI smoke-test mode should parse");
        assert!(arguments.gui_smoke_test);

        let error =
            Arguments::try_parse_from(["hns-dane-browser-setup", "--gui-smoke-test", "--status"])
                .expect_err("GUI smoke testing must not combine with automation");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[cfg(not(feature = "embedded-host"))]
    #[test]
    fn development_cli_accepts_native_host_override() {
        let arguments = Arguments::try_parse_from([
            "hns-dane-browser-setup",
            "--install",
            "--extension-id",
            CANONICAL_EXTENSION_ID,
            "--native-host",
            "development-host",
        ])
        .expect("non-embedded development CLI should accept a native-host override");

        assert_eq!(
            arguments.native_host,
            Some(PathBuf::from("development-host"))
        );
    }
}
