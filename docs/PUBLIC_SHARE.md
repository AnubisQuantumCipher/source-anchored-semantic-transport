# Public share marker

The encoder companion adds a display-only line immediately below the existing
STS1 line:

```text
<the existing readable formula>
STS1:<package integrity digest>
CRED:<SHA-256 of the exact STS1 line>
<the existing package reference>
```

The hash input is the ASCII `STS1:` prefix and its complete lowercase hexadecimal
digest, without a newline. The output uses `CRED:` followed by the complete
lowercase hexadecimal SHA-256. Earlier marker-looking text inside a multiline
formula stays unchanged. No additional source information is introduced.

This is a recognizable package marker. It is not an author signature, a member
credential, or permission to act: anyone who sees STS1 can calculate CRED. A full
SHA-256 marker is not shorter than the existing full digest, and it is computed
from STS1. The formula, lexicon and meaning package still carry the meaning.

## One encoding command

Run the presentation wrapper with an existing qualified decoder installation:

```sh
python3 -I -S -B -Werror install/transport_public_share.py encode \
  --encoder /absolute/decoder/bin/semantic-transport \
  --expect-encoder-sha256 "$HELD_LAUNCHER_SHA256" \
  /absolute/document.json /absolute/new-package /absolute/public-share.txt \
  --source SOURCE=/absolute/source.txt \
  --budget 512 --reference attached:meaning.zip
```

Use `encode-plan` instead of `encode` for the existing plan interface. The supplied
launcher pin must come from the independently held decoder identity. The wrapper
supports the explicitly qualified launcher version; it refuses other launchers.
The launcher continues to check its complete installed bundle. There is no shell,
arbitrary command remainder, network fetch, new installation, or supplied-code
execution in this workflow.

Success produces the existing canonical output directory and a separate
`public-share.txt`. The wrapper passes the same source, reference and budget to
the existing encoder. It then creates the public companion and checks that the
canonical files have not changed. Both output locations must be new, and the
companion must be outside the canonical directory.

The complete public text—including CRED, line breaks and the reference—must fit
the requested Unicode code-point budget and existing UTF-8 byte bound. This is
not a platform-specific character-count promise. Nothing is shortened to fit.
If encoding succeeds but the public text cannot fit, the wrapper reports a
failure, leaves the valid canonical outputs available, and creates no companion.
It never reports complete workflow success in that situation.

## Format an existing share

The helper targets Linux. This command needs Python and the standalone helper,
without running the native decoder:

```sh
python3 -I -S -B -Werror install/transport_public_share.py format \
  examples/quorum-replay-v1/recipient/share.txt /tmp/public-share.txt --budget 512
```

Choose a new output path. Formatting checks the expected share layout; it does
not validate or authenticate a meaning package. Applications may call
`public_text(canonical_share_bytes, budget)` from the same standalone module.

## Recipient boundary

Send the unchanged canonical `share.txt`, matching `meaning.zip`, and declared
decoder dependencies to the recipient. The public companion is for display.
The current decoder compares the complete canonical share byte-for-byte; passing
the decorated companion as that input is rejected. No decoder strips, recognizes
or checks CRED. No manifest includes it.

Keeping these files separate preserves existing packages, runtime identities,
recovery and verification behavior. The companion is an added encoder-facing
presentation step, not a change to the canonical codec format or an installed
decoder upgrade.

## Evidence

The [public-share example and receipt](../examples/public-share-v1/README.md)
record literal formatter controls, boundary refusals, the actual encoder
comparison, and independent review. These are tested presentation and workflow
properties; they add no semantic or formal-proof claim.
