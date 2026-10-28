# Installation on Omarchy

The current route builds a private, versioned runtime directory. It does not request root, download tools, modify a shell profile, register a service, or change client permissions. The installation keeps the existing strict Ada warnings, runtime assertions and validation flags.

## Prerequisites and scope

The exercised environment is Omarchy `4.0.0.alpha` on Arch Linux ARM (`aarch64`), Python `3.14.7`, GNAT/GCC `16.1.0`, GPRbuild `26.0.0`, and GNU readelf `2.46.1`. The source contains an `x86_64` build profile, but that profile has **not been exercised**. Other Python minor versions are rejected. This is not yet a one-click marketplace install.

Provide an existing trusted GNAT compiler toolchain, GPRbuild and readelf. Toolchain acquisition, system updates and third-party installation are outside this command. The installer requires a user-owned parent directory without group/world write permission and reserves `10000000000` bytes of free space plus its declared output allowance.

The compiler is trusted not to escape its process group. Direct process time, output and memory limits do not prove aggregate descendant containment. Uploaded packages and source documents are never passed to the compiler.

## Build

Obtain the source at the intended published commit. Verify `install/SOURCE.json` against the digest supplied with that release or checkpoint. A digest obtained from the same untrusted download is an integrity reference, not independent authentication.

```sh
python3 -I -S -B -Werror install/prepare_source.py --check

mkdir -p -m 700 "$HOME/.local/share/source-anchored-semantic-transport"
mkdir -p -m 700 "$HOME/.local/state/source-anchored-semantic-transport"

python3 -I -S -B -Werror install/transport_install.py build \
  "$HOME/.local/share/source-anchored-semantic-transport/build-1" \
  --expect-source '<SOURCE.json SHA-256 from the checkpoint>' \
  --receipt "$HOME/.local/state/source-anchored-semantic-transport/build-1" \
  --gprbuild '/absolute/path/to/gprbuild' \
  --compiler-bin '/absolute/path/to/gnat/bin'
```

Both the destination and receipt directory must be absent. The receipt parent must already exist. `--compiler-bin` must contain `gcc`, `gnatbind`, `gnatlink` and `readelf`. The selected drivers and their version output are recorded. The complete compiler installation remains a trusted external dependency.

The command copies only the pinned build inputs into private scratch space, builds the unchanged project, rejects unexpected ELF dependencies or embedded search paths, and derives copied module/runtime pins. It verifies the complete staged tree before publishing it atomically without replacing any existing directory. Failure logs are retained in the receipt directory.

For the commands in the README, add the **specific bundle** to PATH in the current shell:

```sh
export PATH="$HOME/.local/share/source-anchored-semantic-transport/build-1/bin:$PATH"
semantic-transport check
```

No mutable `current` link is created. Keep outputs outside the installed directory; unexpected entries inside the bundle cause verification to refuse.

## Independently check generated files

Keep the installation manifest digest from the successful build receipt separately. The following command reconstructs expected generated module and launcher bytes from the pinned source and declared native binary. It does not rebuild or prove the compiler's output.

```sh
python3 -I -S -B -Werror install/transport_install.py check \
  "$HOME/.local/share/source-anchored-semantic-transport/build-1" \
  --expect-source '<SOURCE.json SHA-256>' \
  --expect-install '<INSTALL.json SHA-256 from the build receipt>' \
  --receipt "$HOME/.local/state/source-anchored-semantic-transport/check-1"
```

The launcher checks installed content and declared external identities before dispatch. The trusted entry point is the launcher itself; its embedded digest cannot authenticate a maliciously replaced launcher. Use the source-based check and a separately held manifest digest for that case. The Python standard library, transitive shared libraries and operating system remain trusted.

## Receiving and upgrades

Share the matched `share.txt` and `meaning.zip` plus the exact declared decoder bundle and dependencies. A source rebuild on another machine does not promise the same runtime identity. Keep the old bundle for old packages. Dependency changes cause refusal, not an automatic reinterpretation or migration.

The optional `mcp` command additionally requires the exact SDK and dependency versions declared in `tools/transport_mcp.py`. It never installs them. System site hooks and third-party SDK contents are trusted and version-gated, not content-authenticated. Local stdio protocol testing does not constitute acceptance by a desktop client. No desktop integration is installed automatically.

## Uninstall

The install consists of the one directory you selected and its separately chosen receipt directory. Remove the runtime directory only after retaining any bundles still required to decode existing packages. Remove a manually added PATH entry if you made one. Keep recovery packages and receipts according to your retention policy; the installer does not delete them.
