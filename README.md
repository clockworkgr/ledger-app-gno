# Ledger Gno Application

A Ledger device application that signs [gno.land](https://gno.land) transactions, for Nano X,
Nano S+, Stax, Flex and Apex P.

* Derives tm2 accounts on `m/44'/118'/account'/0/index` and shows `g1...` addresses. "Show
  address" on the home screen displays the address at any index of the first account, typed on
  the device, without a computer.
* Streams the amino sign doc, so payload size is not bounded by device RAM, and accepts only
  the exact bytes gno produces for the supported message types.
* Clear-signs bank sends, realm calls, package approval and rejection, and session keys.
* Package deployment (`m_addpkg`) and scripts (`m_run`) carry source code that cannot be shown on
  a device. They are off by default and, once enabled under Settings > Packages, are signed
  through Ledger's blind-signing flow with a package fingerprint to compare off-device. The
  review also lists the files, and the imports and literal addresses found in the code.

Protocol: [`docs/APDU.md`](docs/APDU.md). Chain rules and signing policy:
[`docs/GNO.instructions.md`](docs/GNO.instructions.md).

Built from [LedgerHQ/app-boilerplate-rust](https://github.com/LedgerHQ/app-boilerplate-rust); the
development environment below is unchanged from it.

### Links

* 📚 [Developer's documentation](https://developers.ledger.com/docs/device-app/getting-started)<br/>
* 🗣️ [Ledger's Discord server](https://discord.gg/Ledger)

## Quick start guide

### With VS Code

You can quickly setup a development environment on any platform (macOS, Linux or Windows) to build and test your application with [Ledger's VS Code extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).

By using Ledger's own developer tools [Docker image](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools), the extension allows you to **build** your apps with the latest SDK, **test** them on **Speculos** and **load** them on any supported device.

* Install and run [Docker](https://www.docker.com/products/docker-desktop/).
* Make sure you have an X11 server running :
  * On Ubuntu Linux, it should be running by default.
  * On macOS, install and launch [XQuartz](https://www.xquartz.org/) (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  * On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/) (make sure to configure it to disable access control).
* Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
* Clone this repository with its submodule (`git clone --recurse-submodules`), and open it with VSCode.
* Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b` (`command + shift + b` on a Mac) to conveniently execute actions :
  * **Build** the app for the device model of your choice with `Build`.
  * **Test** your binary on the [Speculos emulator](https://github.com/LedgerHQ/speculos) with `Run with emulator`.
  * You can also **run functional tests**, load the app on a physical device, and more.

ℹ️ The terminal tab of VSCode will show you what commands the extension runs behind the scene.

## With a terminal

### Prerequisites

If you do not wish to use the [VS Code extension](#with-vs-code), you can follow the following steps to setup a development environment on Linux, Windows or MacOS.

* The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools) Docker image contains all the required tools and libraries to build, test and load an application on a device. You can download it from the ghcr.io docker repository:
```shell
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```
* Make sure you have an X11 server running :
  * On Ubuntu Linux, it should be running by default.
  * On macOS, install and launch [XQuartz](https://www.xquartz.org/) (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  * On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/) (make sure to configure it to disable access control).

There are two ways to use the container, depending on what you are doing.

#### Interactive shell (recommended for development)

Drop into a shell inside the container once, then run as many `cargo ledger build` / `pytest` commands as you like. The bind-mount (`-v .../app`) keeps the build artifacts on your host. The extra `--privileged`, `--publish` and X11 (`DISPLAY`, `/tmp/.X11-unix`) flags are only needed if you intend to run Speculos — they are harmless otherwise.

Run the command matching your OS from the directory of the application (`git` repository):
  * Linux (Ubuntu): 
  ```shell
  sudo docker run --rm -ti --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" --publish 5001:5001 --publish 9999:9999 -e DISPLAY=$DISPLAY -v '/tmp/.X11-unix:/tmp/.X11-unix' ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
  ```
  * macOS:
  ```shell
  docker run  --rm -ti -v "$(pwd -P):/app" --publish 5001:5001 --publish 9999:9999 -e DISPLAY='host.docker.internal:0' ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
  ```
  * Windows (with PowerShell):
  ```shell
  docker run --rm -ti --privileged -v "$(Get-Location):/app" -e DISPLAY='host.docker.internal:0' --publish 5001:5001 --publish 9999:9999 ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
  ```

The application's code is mounted at `/app` inside the container. Once in the shell, proceed to the [Building](#building) and [Testing](#testing) steps below — run those commands inside the container.

#### One-shot command (handy for CI or a quick build)

Instead of opening a shell, append the command to run to `docker run` and the container exits when it finishes. The repository is still mounted at `/app`, so artifacts land in your host `target/` directory. For example, to build for Flex (macOS / Linux):

```shell
docker run --rm -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest cargo ledger build flex
```

Any of the commands from [Building](#building) and [Testing](#testing) can be run this way. Add the `--privileged`, `--publish` and X11 flags shown above if the command needs Speculos (e.g. functional tests).

### Building

You can build the app with the following command executed in the root directory of the app.
```bash
cargo ledger build nanox
```
This command will build the app for the Nano X, but you can use any supported device (`nanox`, `nanosplus`, `stax`, `flex`, `apex_p`).

> ℹ️ `.cargo/config.toml` sets `apex_p` as the default cargo target, so a bare `cargo ledger build` builds for Apex P. Always pass the device explicitly to be sure.

### Testing
#### Parser tests on the host
The sign-doc parser (`src/tx`) has no device dependency and is tested on the host against
payloads rendered by upstream gno (`tests/vectors/sign_docs.json`, produced by `tools/vectors`):
```bash
cd host-tests && cargo +stable test
```
Use a stable toolchain: `rust-toolchain.toml` pins the device nightly, which would apply the root
config's `build-std` to the host build and fail.
#### Fuzzing
`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the sign-doc parser
(checked against a Go-style JSON re-encoder and for chunking-independent results), the DER signature
conversion and the package source scanner. They run in CI through ClusterFuzzLite. To run one
locally (needs rustup, a nightly toolchain and `cargo install cargo-fuzz`):
```bash
./fuzz/run.sh fuzz_parser 300        # target, seconds; also fuzz_der, fuzz_source
```
The script builds from a copy outside the repository, because `.cargo/config.toml` configures the
device build. The corpus and any crash inputs are kept in `fuzz/work/`.
#### Ragger functional tests
Functional tests use Ledger's [Ragger](https://github.com/LedgerHQ/ragger) framework, in `tests/standalone/`.

* Install the tests requirements
```bash
pip install -r tests/standalone/requirements.txt
```
* Run the standalone functional tests :

```shell
pytest tests/standalone/ --tb=short -v --device {nanosp | nanox | stax | flex | apex_p}
```

> ℹ️ Speculos uses `nanosp` for Nano S+ (whereas `ledger_app.toml` lists it as `nanos+`).
#### Emulator
You can also run the app directly on the [Speculos emulator](https://github.com/LedgerHQ/speculos) from the Docker container
#### Nano S+ or X
```bash
speculos --apdu-port 9999 --api-port 5001 --display headless target/nanosplus/release/app-gno
```
:warning: UI is displayed on `localhost:5001`
#### Stax, Flex or Apex P
```bash
speculos --apdu-port 9999 --api-port 5001 target/stax/release/app-gno
```

:warning: UI is displayed by your X server

You can then send APDU using `ledgercomm` (`pip install ledgercomm`):
```
ledgercomm-send file test.apdu
```
### Loading on device
Recent versions of [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger) no longer emit a `ledgerctl` JSON manifest. Instead, loading is handled through [ledgerblue](https://pypi.org/project/ledgerblue/): the build generates an APDU install script and, when `--load` (or `-l`) is passed, runs it on the connected device with `python3 -m ledgerblue.runScript --targetId <id> --fileName <script> --apdu --scp`.

:warning: Loading must be performed **out of the Docker container** (it needs USB access to the device).

* Install `ledgerblue`:
```shell
pip3 install ledgerblue
```
* Load on device, e.g. for Flex:
```bash
python3 -m ledgerblue.runScript --targetId <id> --fileName target/flex/release/app-gno.apdu --apdu --scp
```

ℹ️ Your device must be connected, unlocked and the screen showing the dashboard (not inside an application).

#### About the device target ID

ledgerblue needs the device's `targetId`. 

If you call ledgerblue manually, note that its `--targetId` defaults to `0x31100002` (Nano S) — wrong for every other device, and it is **not** auto-detected from the connected device. The cleanest option is to let ledgerblue read the id straight from the ELF with `--elfFile`, which overrides `--targetId`:
```bash
python3 -m ledgerblue.runScript --elfFile target/flex/release/app-gno --fileName <install_script> --apdu --scp
```

If you instead need the raw target ID value (e.g. for a CI script), the [`tools/get_target_id.py`](tools/get_target_id.py) helper extracts it from the `ledger.target_id` ELF section:
```bash
python3 tools/get_target_id.py target/flex/release/app-gno   # -> 0x33300004
```

#### For end users: standalone installer

Each GitHub release ships ready-to-run installers (Linux, Windows, macOS) that embed the release binaries and sideload the app without git, Docker or Python. See [`tools/sideload/README.md`](tools/sideload/README.md).

## Continuous Integration
The following workflows are executed in [GitHub Actions](https://github.com/features/actions) :

* Ledger guidelines enforcer which verifies that an app is compliant with Ledger guidelines. The successful completion of this reusable workflow is a mandatory step for an app to be available on the Ledger application store. More information on the guidelines can be found in the repository [ledger-app-workflow](https://github.com/LedgerHQ/ledger-app-workflows)
* Compilation of the application for all supported devices in the [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder) docker image
* End-to-end tests with the [Speculos](https://github.com/LedgerHQ/speculos) emulator and [ragger](https://github.com/LedgerHQ/ragger) (see [tests/](tests/))
* Host-side parser tests, and a check that `tests/vectors` still matches the pinned gno version
* CodeQL analysis (`security-and-quality` queries) of the Rust sources, workflows and test client
* ClusterFuzzLite fuzzing of the parser, signature conversion and source scanner (pull requests,
  pushes and a weekly long run)
* `cargo audit` of the app's and the host tests' dependencies
* Various lint checks :
  * Source code lint checks with `cargo fmt`
  * Python functional test code lint checks with `pylint` and `mypy`
