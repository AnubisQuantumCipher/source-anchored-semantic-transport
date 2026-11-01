# FT01 framed native decode boundary

`document_native_decode INPUT_FILE` accepts exactly one binary FT01 file.
It writes recovered source bytes to stdout, no diagnostics there. Any malformed
input or IO failure exits nonzero with one fixed stderr line, `FT01 input refused`.
Stdout is provisional, including after a later-frame error. The caller must redirect
it to a private regular temporary file, validate process success, exact total length
and whole-source SHA256, then publish by its separately checked create-only boundary.
This executable parses no ZIP, JSON, PDF, EPUB or source instructions.

All integer fields are unsigned big-endian; no padding or native endian fields:

| Field | Bytes |
| --- | ---: |
| ASCII magic `FT01` | 4 |
| Total recovered source length | 8 |
| Declared frame count | 4 |

Exactly the declared number of records follows:

| Record field | Bytes |
| --- | ---: |
| Zero-based ordinal | 4 |
| Global recovered-source offset | 8 |
| Recovered source size | 4 |
| STB1 wire size | 4 |
| Exact STB1 wire bytes | wire size |

EOF is required after the final record. Total source is at most 1073741824 bytes,
frame source at most 65536 bytes, frame wire at most 131072 bytes and count at most
16384. Count equals ceil(total / 65536); empty input has total/count zero and no
records. Every frame is nonempty and full-sized except the final frame. Ordinals
and offsets must be contiguous from zero. Decoding must return Ok and Used equal
to the record's source size. Existing Transport_Decoder and dependencies are reused
byte-for-byte. FT01 carries no cryptographic hashes: the surrounding document
profile binds per-frame, dependency and whole-source hashes independently.

## Ledger API and proved scope

`Document_Frame_Ledger.Initialize(Item, Total, Declared)` always produces a Valid
state, zero accepted frames/bytes, the required count, and Rejected precisely for a
count mismatch. `Accept_Frame` requires Valid state and accepts only Admissible
ordinal/offset/length. On acceptance it preserves total/count, advances count by one
and bytes by size, and preserves Valid. On refusal it sets sticky Rejected and
leaves counters unchanged. `Complete` requires Valid, not Rejected, and exact count
and byte completion. `Next_Length` gives the remaining full or final frame length.
The public record is integration state; callers must honor Valid preconditions and
must not manufacture states. The native IO adapter initializes and mutates it only
through the two ledger procedures.

The proof project explicitly selects only document_frame_ledger.ads/.adb. The
retained report proves all 16 checks for that one unit, with no justified/unproved
checks. This does not rerun the original 1368 checks, prove IO, cryptography, ZIP,
Python, text extraction or semantic interpretation, or establish a fresh complete
original native proof reproduction.

## Reproducible development evidence

Build/proof driver: `python -I -S -W error document_native/qualify_native.py NAME`
uses fresh named evidence, 120s build / 300s proof / 450s outer, AS 1GiB, strict Ada
warnings-as-errors and runtime contracts. Outputs/temp/cache stay under the pinned
native tmpfs subtree, with monitored 512MiB/8192-entry bounds. `--build-only` does not
rerun an unchanged ledger proof. A fresh invocation must use a fresh alphanumeric
NAME; the current versioned binary is frozen, not overwritten by later builds.

Native controls used an independent literal STB1 encoder and literal FT01 packing,
not the document archive implementation. 43 cases cover exact binary multiframe
recovery, empty/full frames, record continuity, bounds, truncation, EOF, invalid
STB1 and decoder Used mismatch. Contract-enabled Ada controls include maximum-size
ledger completion without allocating the document, sticky refusal, nonfinal/final
sizes, offset/ordinal bounds and count mismatch. Source snapshots and raw process
logs are retained under the native scratch directory. Independent review remains a
separate gate.
