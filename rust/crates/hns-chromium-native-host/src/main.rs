use hns_chromium_native_host::{
    LocalCaStore, NativeHostController, native_messaging_host_manifest_json, serve_native_messaging,
};
use hns_chromium_platform_runtime::{NetworkKind, chromium_dane_pac_script};
use std::env;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("hns-chromium-native-host: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::parse(env::args().skip(1))?;
    let data_dir = options.data_dir.unwrap_or_else(default_data_dir);
    match options.command {
        UtilityCommand::PrintPac(port) => {
            print!(
                "{}",
                chromium_dane_pac_script(port).map_err(|error| error.to_string())?
            );
            return Ok(());
        }
        UtilityCommand::CaInfo => {
            let store = LocalCaStore::open(&data_dir).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store.status_json())
                    .map_err(|error| error.to_string())?
            );
            return Ok(());
        }
        UtilityCommand::MarkCaInstalled => {
            LocalCaStore::open(&data_dir)
                .and_then(|store| store.mark_installed())
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        UtilityCommand::ClearCaInstalled => {
            LocalCaStore::open(&data_dir)
                .and_then(|store| store.clear_installed_marker())
                .map_err(|error| error.to_string())?;
            return Ok(());
        }
        UtilityCommand::PrintHostManifest => {
            let executable = std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .map_err(|error| format!("unable to resolve native-host executable: {error}"))?;
            print!(
                "{}",
                native_messaging_host_manifest_json(&executable, &options.extension_ids)
                    .map_err(|error| error.to_string())?
            );
            return Ok(());
        }
        UtilityCommand::Serve => {}
    }

    configure_native_stdio()?;
    let mut controller = NativeHostController::open(&data_dir, options.network)
        .map_err(|error| error.to_string())?;
    serve_native_messaging(
        &mut controller,
        &mut BufReader::new(std::io::stdin().lock()),
        &mut BufWriter::new(std::io::stdout().lock()),
    )
    .map_err(|error| error.to_string())
}

struct Options {
    data_dir: Option<PathBuf>,
    network: NetworkKind,
    command: UtilityCommand,
    extension_ids: Vec<String>,
}

enum UtilityCommand {
    Serve,
    PrintPac(u16),
    CaInfo,
    MarkCaInstalled,
    ClearCaInstalled,
    PrintHostManifest,
}

impl Options {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = Self {
            data_dir: None,
            network: NetworkKind::Mainnet,
            command: UtilityCommand::Serve,
            extension_ids: Vec::new(),
        };
        let arguments = arguments.collect::<Vec<_>>();
        let mut index = 0;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--data-dir" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| "--data-dir requires a path".to_owned())?;
                    options.data_dir = Some(PathBuf::from(value));
                }
                "--network" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| "--network requires a value".to_owned())?;
                    options.network = value
                        .parse()
                        .map_err(|_| "--network must be mainnet, testnet, or regtest".to_owned())?;
                }
                "--print-pac" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| "--print-pac requires a port".to_owned())?;
                    options.set_command(UtilityCommand::PrintPac(
                        value
                            .parse()
                            .map_err(|_| "--print-pac port is invalid".to_owned())?,
                    ))?;
                }
                "--ca-info" => options.set_command(UtilityCommand::CaInfo)?,
                "--mark-ca-installed" => {
                    options.set_command(UtilityCommand::MarkCaInstalled)?;
                }
                "--clear-ca-installed" => {
                    options.set_command(UtilityCommand::ClearCaInstalled)?;
                }
                "--print-host-manifest" => {
                    options.set_command(UtilityCommand::PrintHostManifest)?;
                }
                "--extension-id" => {
                    index += 1;
                    let value = arguments
                        .get(index)
                        .ok_or_else(|| "--extension-id requires an ID".to_owned())?;
                    options.extension_ids.push(value.clone());
                }
                value
                    if value.starts_with("chrome-extension://")
                        || value.starts_with("--parent-window=") => {}
                value => return Err(format!("unsupported argument: {value}")),
            }
            index += 1;
        }
        if !matches!(options.command, UtilityCommand::PrintHostManifest)
            && !options.extension_ids.is_empty()
        {
            return Err("--extension-id requires --print-host-manifest".to_owned());
        }
        Ok(options)
    }

    fn set_command(&mut self, command: UtilityCommand) -> Result<(), String> {
        if !matches!(self.command, UtilityCommand::Serve) {
            return Err("only one native-host utility command may be used".to_owned());
        }
        self.command = command;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn configure_native_stdio() -> Result<(), String> {
    const STDIN_FILE_DESCRIPTOR: i32 = 0;
    const STDOUT_FILE_DESCRIPTOR: i32 = 1;
    const O_BINARY: i32 = 0x8000;
    unsafe extern "C" {
        fn _setmode(file_descriptor: i32, mode: i32) -> i32;
    }
    // SAFETY: Chrome's documented native-messaging contract requires the
    // inherited CRT stdin/stdout descriptors to use binary mode. The values
    // are process-local standard descriptors and `_setmode` does not retain
    // pointers or cross the Rust ownership boundary.
    if unsafe { _setmode(STDIN_FILE_DESCRIPTOR, O_BINARY) } == -1
        || unsafe { _setmode(STDOUT_FILE_DESCRIPTOR, O_BINARY) } == -1
    {
        return Err("unable to set native-messaging stdio to binary mode".to_owned());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn configure_native_stdio() -> Result<(), String> {
    Ok(())
}

fn default_data_dir() -> PathBuf {
    if let Some(path) = env::var_os("HNS_CHROMIUM_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = installed_data_dir() {
        return path;
    }
    if cfg!(target_os = "windows") {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("HnsDaneBrowser")
            .join("Chromium")
    } else if cfg!(target_os = "macos") {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("Library")
            .join("Application Support")
            .join("HnsDaneBrowser")
            .join("Chromium")
    } else {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
            })
            .unwrap_or_else(env::temp_dir)
            .join("hns-dane-browser")
            .join("chromium")
    }
}

fn installed_data_dir() -> Option<PathBuf> {
    let executable = env::current_exe().ok()?;
    let executable_name = executable.file_name()?.to_str()?;
    if executable_name != "hns-chromium-native-host"
        && executable_name != "hns-chromium-native-host.exe"
    {
        return None;
    }
    let binary_directory = executable.parent()?;
    if binary_directory.file_name()? != "bin" {
        return None;
    }
    Some(binary_directory.parent()?.join("data"))
}
