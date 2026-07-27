use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

/// Desktop Chromium distributions supported by the native host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Browser {
    Chrome,
    Chromium,
    Edge,
    Brave,
    Vivaldi,
    Opera,
}

impl Browser {
    pub const ALL: [Self; 6] = [
        Self::Chrome,
        Self::Chromium,
        Self::Edge,
        Self::Brave,
        Self::Vivaldi,
        Self::Opera,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
            Self::Edge => "edge",
            Self::Brave => "brave",
            Self::Vivaldi => "vivaldi",
            Self::Opera => "opera",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Chrome => "Google Chrome",
            Self::Chromium => "Chromium",
            Self::Edge => "Microsoft Edge",
            Self::Brave => "Brave",
            Self::Vivaldi => "Vivaldi",
            Self::Opera => "Opera",
        }
    }
}

impl fmt::Display for Browser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.id())
    }
}

impl FromStr for Browser {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|browser| browser.id() == value)
            .ok_or_else(|| format!("unsupported Chromium browser: {value}"))
    }
}

/// Explicit user selection plus the browsers observed on this system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSelection {
    pub detected: BTreeSet<Browser>,
    pub selected: BTreeSet<Browser>,
}

impl BrowserSelection {
    pub fn detected_defaults() -> Self {
        let detected = detect_browsers();
        let selected = if detected.is_empty() {
            Browser::ALL.into_iter().collect()
        } else {
            detected.clone()
        };
        Self { detected, selected }
    }
}

/// Browser detection is advisory. Installation always follows the user's
/// explicit selection and never treats an absent executable as authorization
/// to modify a different browser.
pub fn detect_browsers() -> BTreeSet<Browser> {
    Browser::ALL
        .into_iter()
        .filter(|browser| {
            browser_candidates(*browser)
                .iter()
                .any(|path| path.exists())
        })
        .collect()
}

fn browser_candidates(browser: Browser) -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let commands: &[&str] = match browser {
            Browser::Chrome => &["google-chrome", "google-chrome-stable"],
            Browser::Chromium => &["chromium", "chromium-browser"],
            Browser::Edge => &["microsoft-edge", "microsoft-edge-stable"],
            Browser::Brave => &["brave-browser", "brave-browser-stable"],
            Browser::Vivaldi => &["vivaldi", "vivaldi-stable"],
            Browser::Opera => &["opera"],
        };
        return commands
            .iter()
            .flat_map(|command| path_command_candidates(command))
            .collect();
    }

    #[cfg(target_os = "macos")]
    {
        let application = match browser {
            Browser::Chrome => "Google Chrome.app",
            Browser::Chromium => "Chromium.app",
            Browser::Edge => "Microsoft Edge.app",
            Browser::Brave => "Brave Browser.app",
            Browser::Vivaldi => "Vivaldi.app",
            Browser::Opera => "Opera.app",
        };
        return vec![
            Path::new("/Applications").join(application),
            home_directory()
                .unwrap_or_default()
                .join("Applications")
                .join(application),
        ];
    }

    #[cfg(target_os = "windows")]
    {
        let relative_paths: &[&str] = match browser {
            Browser::Chrome => &["Google/Chrome/Application/chrome.exe"],
            Browser::Chromium => &["Chromium/Application/chrome.exe"],
            Browser::Edge => &["Microsoft/Edge/Application/msedge.exe"],
            Browser::Brave => &["BraveSoftware/Brave-Browser/Application/brave.exe"],
            Browser::Vivaldi => &["Vivaldi/Application/vivaldi.exe"],
            Browser::Opera => &["Programs/Opera/opera.exe"],
        };
        let bases = [
            std::env::var_os("LOCALAPPDATA"),
            std::env::var_os("PROGRAMFILES"),
            std::env::var_os("PROGRAMFILES(X86)"),
        ];
        return bases
            .into_iter()
            .flatten()
            .flat_map(|base| {
                relative_paths
                    .iter()
                    .map(move |relative| PathBuf::from(&base).join(relative))
            })
            .collect();
    }

    #[allow(unreachable_code)]
    Vec::new()
}

#[cfg(target_os = "linux")]
fn path_command_candidates(command: &str) -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .map(|base| base.join(command))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_ids_round_trip() {
        for browser in Browser::ALL {
            assert_eq!(browser.id().parse::<Browser>(), Ok(browser));
        }
    }

    #[test]
    fn unsupported_browser_is_rejected() {
        assert!("chrome-canary".parse::<Browser>().is_err());
    }
}
