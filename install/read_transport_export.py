#!/usr/bin/env python3
"""Bounded informational reader for the frozen transport/export/1 contract.

This independent implementation does not import or execute a producer.  Its
checks establish consistency with a caller-held export pin, not authenticity,
native decoding, original-source equality, semantic completeness, or proof.
Python, the OS, and SHA256 collision resistance remain assumptions.  Hostile
concurrent mutation by the same OS user is not fully isolated.

The API does not alter its caller's process limits.  The CLI caps address space
at 268435456 bytes, CPU at 60 seconds, and file size at 131072 bytes; an existing
stricter limit is preserved.  Paths are bounded to 4096 UTF-8 bytes and 256
components.  No directory, source program, or executable is created or run.

Success requires a complete bounded JSON line and exit status zero.  Positive
short stream writes are completed with bounded retries.  An irrecoverable
stream failure can leave a prefix that cannot be rolled back; consumers must
never accept that prefix as a successful receipt.  Such failures return nonzero
and trigger cleanup of a newly created output file before commitment.
"""

import argparse
import errno
import hashlib
import json
import os
import re
import resource
import stat
import sys


MAX_BYTES = 131072
MAX_SOURCE_BYTES = 65536
MAX_SOURCES = 16
MAX_DEPTH = 12
MAX_FIELDS = 256
MAX_NODES = 131072
MAX_PATH_BYTES = 4096
MAX_PATH_PARTS = 256
TEXT_PATH = "UNVERIFIED_AI_EXPLANATION.txt"
HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
SOURCE_ID = re.compile(r"[A-Z][A-Z0-9_]{0,31}", re.ASCII)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
RECONSTRUCTION = (
    "Use schema, package_identity, ordered sources, and strict UTF-8 text "
    "artifact; raw input JSON serialization is not reconstructed."
)
ASSURANCE = {
    "source_bytes": "EXACT_NATIVE_DECODED_AND_HASH_CHECKED",
    "declarations": "UNVERIFIED",
    "author_authentication": "NOT_AUTHENTICATED",
    "factual_truth": "NOT_CERTIFIED",
    "semantic_completeness": "NOT_CLAIMED",
    "explanation_entailment": "UNPROVEN",
    "execution_authority": "NONE",
}
CLAIMS = {
    "metadata": "UNVERIFIED",
    "declarations": "UNVERIFIED",
    "authentication": "NOT_PROVIDED",
    "authority": "NONE",
    "original_comparison": "NOT_PERFORMED",
    "producer_runtime": "NOT_EXECUTED",
    "raw_envelope": "NOT_RECONSTRUCTED",
    "semantic_completeness": "NOT_CLAIMED",
    "explanation_entailment": "UNPROVEN",
}


class ExportReadError(Exception):
    """A refusal with a stable code; messages never contain input bodies."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise ExportReadError(code)


def _exact_keys(value, names, code="SCHEMA_KEYS"):
    _require(type(value) is dict, "SCHEMA_TYPE")
    _require(set(value) == set(names), code)


def _digest(value):
    _require(type(value) is str and HEX.fullmatch(value) is not None,
             "DIGEST_FORMAT")


def _integer(value, maximum, minimum=0):
    _require(type(value) is int and minimum <= value <= maximum,
             "INTEGER_BOUND")


def _string(value, nonempty=False):
    _require(type(value) is str, "SCHEMA_TYPE")
    _require(not nonempty or bool(value), "STRING_EMPTY")


def _identity(value):
    _string(value)
    _require(value.startswith("STS1:") and len(value) == 69,
             "IDENTITY_FORMAT")
    _digest(value[5:])


def _record(value, keys, maximum=MAX_BYTES, path=None):
    _exact_keys(value, keys)
    _integer(value["bytes"], maximum)
    _digest(value["sha256"])
    if "path" in value:
        _string(value["path"])
        if path is not None:
            _require(value["path"] == path, "PATH_MISMATCH")
    if "id" in value:
        _require(type(value["id"]) is str and
                 SOURCE_ID.fullmatch(value["id"]) is not None, "SOURCE_ID")


def _lexical_guard(text):
    """Bound parser recursion before allowing the standard JSON decoder."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            _require(depth <= MAX_DEPTH, "JSON_DEPTH")
        elif character in "]}":
            depth -= 1
            _require(depth >= 0, "JSON_SYNTAX")
    _require(not in_string and depth == 0, "JSON_SYNTAX")


def _json_integer(token):
    digits = token[1:] if token.startswith("-") else token
    _require(len(digits) <= 20, "JSON_INTEGER_DIGITS")
    return int(token)


def _json_noninteger(_token):
    raise ExportReadError("JSON_NONINTEGER")


def _json_pairs(pairs):
    _require(len(pairs) <= MAX_FIELDS, "JSON_FIELDS")
    result = {}
    for key, value in pairs:
        _require(key not in result, "JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _string_cost(value):
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise ExportReadError("JSON_UNICODE") from None


def _tree_guard(value):
    pending = [value]
    nodes = 0
    string_bytes = 0
    for _ in range(MAX_NODES + 1):
        if not pending:
            return
        item = pending.pop()
        nodes += 1
        if type(item) is dict:
            _require(len(item) <= MAX_FIELDS, "JSON_FIELDS")
            nodes += len(item)
            for key in item:
                string_bytes += _string_cost(key)
            children = item.values()
        elif type(item) is list:
            children = item
        else:
            _require(type(item) in (str, int, bool, type(None)), "JSON_TYPE")
            if type(item) is str:
                string_bytes += _string_cost(item)
            children = ()
        _require(nodes + len(pending) + len(children) <= MAX_NODES,
                 "JSON_NODES")
        _require(string_bytes <= MAX_BYTES, "JSON_STRING_BYTES")
        pending.extend(children)
    raise ExportReadError("JSON_NODES")


def _parse_json(raw):
    _require(0 < len(raw) <= MAX_BYTES, "JSON_SIZE")
    _require(not raw.startswith(b"\xef\xbb\xbf"), "JSON_BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
        _lexical_guard(text)
        value = json.loads(text, object_pairs_hook=_json_pairs,
                           parse_int=_json_integer,
                           parse_float=_json_noninteger,
                           parse_constant=_json_noninteger)
    except UnicodeError:
        raise ExportReadError("JSON_UNICODE") from None
    except (ValueError, RecursionError):
        raise ExportReadError("JSON_SYNTAX") from None
    _tree_guard(value)
    return value


def _path_parts(path):
    try:
        path = os.fspath(path)
        _require(type(path) is str and bool(path), "PATH_INVALID")
        _require("\\" not in path and "\x00" not in path, "PATH_INVALID")
        _require(len(path.encode("utf-8", errors="strict")) <= MAX_PATH_BYTES,
                 "PATH_BOUND")
        if not path.startswith("/"):
            path = os.getcwd() + "/" + path
        _require(len(path.encode("utf-8", errors="strict")) <= MAX_PATH_BYTES,
                 "PATH_BOUND")
    except (TypeError, UnicodeError):
        raise ExportReadError("PATH_INVALID") from None
    parts = path.split("/")
    _require(len(parts) <= MAX_PATH_PARTS + 1, "PATH_BOUND")
    _require(".." not in parts, "PATH_TRAVERSAL")
    _require(all(len(part.encode("utf-8")) <= 255 for part in parts),
             "PATH_BOUND")
    return [part for part in parts if part not in ("", ".")]


def _open_directory(parts):
    descriptor = os.open("/", DIR_FLAGS)
    try:
        _require(stat.S_ISDIR(os.fstat(descriptor).st_mode), "FILESYSTEM_TYPE")
        for part in parts:
            child = os.open(part, DIR_FLAGS, dir_fd=descriptor)
            try:
                _require(stat.S_ISDIR(os.fstat(child).st_mode),
                         "FILESYSTEM_TYPE")
            except BaseException:
                os.close(child)
                raise
            previous = descriptor
            descriptor = child
            os.close(previous)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _names(descriptor, maximum):
    names = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            _require(len(names) < maximum, "FILESYSTEM_ENTRY_BOUND")
            _require(entry.name not in names, "FILESYSTEM_DUPLICATE_ENTRY")
            names.add(entry.name)
    return names


def _file_stat(information):
    _require(not stat.S_ISLNK(information.st_mode), "FILESYSTEM_SYMLINK")
    _require(stat.S_ISREG(information.st_mode), "FILESYSTEM_TYPE")
    _require(information.st_nlink == 1, "FILESYSTEM_HARDLINK")


def _file_identity(information):
    return information.st_dev, information.st_ino


def _read_descriptor(descriptor, limit):
    data = bytearray()
    for _ in range(limit + 2):
        piece = os.read(descriptor, min(65536, limit - len(data) + 1))
        if not piece:
            return bytes(data)
        _require(len(data) + len(piece) <= limit, "ARTIFACT_SIZE")
        data.extend(piece)
    raise ExportReadError("READ_BOUND")


def _read_member(directory, name, limit, seen):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    _file_stat(before)
    _require(0 <= before.st_size <= limit, "ARTIFACT_SIZE")
    descriptor = os.open(name, READ_FLAGS, dir_fd=directory)
    try:
        opened = os.fstat(descriptor)
        _file_stat(opened)
        identity = _file_identity(opened)
        _require(identity == _file_identity(before), "FILESYSTEM_CHANGED")
        _require(identity not in seen, "FILESYSTEM_ALIAS")
        seen.add(identity)
        _require(0 <= opened.st_size <= limit, "ARTIFACT_SIZE")
        raw = _read_descriptor(descriptor, limit)
        after = os.fstat(descriptor)
        _file_stat(after)
        _require(_file_identity(after) == identity and
                 after.st_size == opened.st_size == len(raw) and
                 after.st_mtime_ns == opened.st_mtime_ns and
                 after.st_ctime_ns == opened.st_ctime_ns, "FILESYSTEM_CHANGED")
        return raw
    finally:
        os.close(descriptor)


def _validate_sources(sources):
    _require(type(sources) is list and 1 <= len(sources) <= MAX_SOURCES,
             "SOURCE_COUNT")
    identifiers = set()
    total = 0
    for item in sources:
        _record(item, ("id", "bytes", "sha256", "path"), MAX_SOURCE_BYTES)
        identifier = item["id"]
        _require(identifier not in identifiers, "SOURCE_DUPLICATE")
        identifiers.add(identifier)
        _require(item["path"] == "sources/" + identifier + ".bin",
                 "PATH_MISMATCH")
        total += item["bytes"]
        _require(total <= MAX_SOURCE_BYTES, "SOURCE_TOTAL")


def _source_projection(sources):
    return [{key: item[key] for key in ("id", "bytes", "sha256")}
            for item in sources]


def _validate_roster(manifest):
    files = manifest["files"]
    _require(type(files) is list and 3 <= len(files) <= 18, "ROSTER_COUNT")
    expected = {item["path"] for item in manifest["sources"]}
    expected.update(("metadata.json", TEXT_PATH))
    roster = {}
    ordered = []
    total = 0
    for item in files:
        _record(item, ("path", "bytes", "sha256"))
        path = item["path"]
        _require(path in expected, "ROSTER_PATH")
        _require(path not in roster, "ROSTER_DUPLICATE")
        if path == TEXT_PATH or path.startswith("sources/"):
            _integer(item["bytes"], MAX_SOURCE_BYTES)
        total += item["bytes"]
        _require(total <= MAX_BYTES, "EXPORT_TOTAL")
        roster[path] = item
        ordered.append(path)
    _require(set(roster) == expected, "ROSTER_MEMBERSHIP")
    _require(ordered == sorted(ordered), "ROSTER_ORDER")
    for item in manifest["sources"]:
        projection = {key: item[key] for key in ("path", "bytes", "sha256")}
        _require(projection == roster[item["path"]], "SOURCE_ROSTER_MISMATCH")
    return roster


def _validate_explanation(manifest, roster):
    value = manifest["explanation"]
    _exact_keys(value, ("schema", "package_identity", "sources", "text_artifact",
                        "input_envelope_bytes", "input_envelope_sha256", "role",
                        "execution_authority", "factual_certification",
                        "logical_envelope_reconstruction"))
    _require(value["schema"] == "transport/explanation-envelope/1", "SCHEMA_VERSION")
    _require(value["package_identity"] == manifest["package_identity"],
             "IDENTITY_MISMATCH")
    sources = value["sources"]
    _require(type(sources) is list and len(sources) == len(manifest["sources"]),
             "EXPLANATION_SOURCES")
    for item in sources:
        _record(item, ("id", "bytes", "sha256"), MAX_SOURCE_BYTES)
    _require(sources == _source_projection(manifest["sources"]),
             "EXPLANATION_SOURCES")
    _record(value["text_artifact"], ("path", "bytes", "sha256"),
            MAX_SOURCE_BYTES, TEXT_PATH)
    _require(value["text_artifact"] == roster[TEXT_PATH], "EXPLANATION_ROSTER")
    _integer(value["input_envelope_bytes"], MAX_SOURCE_BYTES, 1)
    _digest(value["input_envelope_sha256"])
    constants = {"role": "UNVERIFIED_AI_EXPLANATION", "execution_authority": "NONE",
                 "factual_certification": "NOT_PERFORMED",
                 "logical_envelope_reconstruction": RECONSTRUCTION}
    _require(all(value[key] == expected for key, expected in constants.items()),
             "EXPLANATION_AUTHORITY")


def _validate_runtime(value):
    _exact_keys(value, ("schema", "renderer", "base_manifest", "base_decoder",
                        "boundary"))
    _require(value["schema"] == "transport/export-runtime/1", "SCHEMA_VERSION")
    _record(value["renderer"], ("path", "bytes", "sha256"),
            path="tools/transport_export.py")
    _record(value["base_manifest"], ("path", "bytes", "sha256"),
            path="RUNTIME.json")
    decoder = value["base_decoder"]
    _require(type(decoder) is dict, "SCHEMA_TYPE")
    _require(decoder.get("schema") == "transport/runtime/1" and
             decoder.get("decoder") == "transport/transport/2", "SCHEMA_VERSION")
    _string(value["boundary"])


def _validate_manifest(manifest):
    _exact_keys(manifest, ("schema", "package_identity", "sources", "explanation",
                           "inputs", "metadata_artifact", "runtime", "files",
                           "assurance"))
    _require(manifest["schema"] == "transport/export/1", "SCHEMA_VERSION")
    _identity(manifest["package_identity"])
    _require(manifest["metadata_artifact"] == "metadata.json", "PATH_MISMATCH")
    _validate_sources(manifest["sources"])
    roster = _validate_roster(manifest)
    _validate_explanation(manifest, roster)
    _exact_keys(manifest["inputs"], ("share", "archive"))
    for record in manifest["inputs"].values():
        _record(record, ("bytes", "sha256"))
    _exact_keys(manifest["assurance"], ASSURANCE)
    _require(manifest["assurance"] == ASSURANCE, "ASSURANCE_DECLARATION")
    _validate_runtime(manifest["runtime"])
    return roster


def _validate_metadata(metadata, manifest):
    _require(type(metadata) is dict, "SCHEMA_TYPE")
    version = metadata.get("schema")
    _require(version in ("transport/decoded/1", "transport/decoded/2"),
             "SCHEMA_VERSION")
    keys = ("schema", "identity", "sources", "interpretations", "uncertainties",
            "relations", "coverage", "assurance")
    if version == "transport/decoded/2":
        keys += ("meaning_units",)
    _exact_keys(metadata, keys)
    _require(metadata["identity"] == manifest["package_identity"], "IDENTITY_MISMATCH")
    sources = metadata["sources"]
    _require(type(sources) is list and len(sources) == len(manifest["sources"]),
             "METADATA_SOURCES")
    for supplied, expected in zip(sources, manifest["sources"]):
        _record(supplied, ("id", "label", "media_type", "provenance", "bytes",
                           "sha256"), MAX_SOURCE_BYTES)
        _string(supplied["label"])
        _string(supplied["media_type"], nonempty=True)
        _string(supplied["provenance"])
        _require(all(supplied[key] == expected[key]
                     for key in ("id", "bytes", "sha256")), "METADATA_SOURCES")
    for key in ("interpretations", "uncertainties", "relations"):
        _require(type(metadata[key]) is list, "SCHEMA_TYPE")
    if version == "transport/decoded/2":
        _require(type(metadata["meaning_units"]) is list, "SCHEMA_TYPE")
    _require(type(metadata["coverage"]) is dict and
             type(metadata["assurance"]) is dict, "SCHEMA_TYPE")


def _checked_member(directory, name, record, remaining, seen):
    _require(record["bytes"] <= remaining, "EXPORT_TOTAL")
    raw = _read_member(directory, name, min(record["bytes"], remaining), seen)
    _require(len(raw) == record["bytes"], "ARTIFACT_LENGTH")
    _require(hashlib.sha256(raw).hexdigest() == record["sha256"], "ARTIFACT_DIGEST")
    return raw


def _load_export(root, source_directory, expected_pin, source_names, seen):
    raw_manifest = _read_member(root, "export.json", MAX_BYTES, seen)
    _require(hashlib.sha256(raw_manifest).hexdigest() == expected_pin, "EXPORT_PIN")
    manifest = _parse_json(raw_manifest)
    roster = _validate_manifest(manifest)
    _require(source_names == {item["id"] + ".bin" for item in manifest["sources"]},
             "FILESYSTEM_MEMBERSHIP")
    remaining = MAX_BYTES - len(raw_manifest)
    metadata_bytes = _checked_member(root, "metadata.json", roster["metadata.json"],
                                     remaining, seen)
    remaining -= len(metadata_bytes)
    explanation_bytes = _checked_member(root, TEXT_PATH, roster[TEXT_PATH],
                                        remaining, seen)
    remaining -= len(explanation_bytes)
    try:
        explanation_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        raise ExportReadError("TEXT_UNICODE") from None
    sources = []
    for item in manifest["sources"]:
        raw = _checked_member(source_directory, item["id"] + ".bin",
                              roster[item["path"]], remaining, seen)
        remaining -= len(raw)
        sources.append(dict(item, data=raw))
    metadata = _parse_json(metadata_bytes)
    _validate_metadata(metadata, manifest)
    return {"status": "VERIFIED_AGAINST_PINNED_EXPORT", "authority": "NONE",
            "manifest": manifest, "sources": sources,
            "explanation_bytes": explanation_bytes, "metadata_bytes": metadata_bytes,
            "metadata": metadata, "expected_export_sha256": expected_pin,
            "claims": dict(CLAIMS)}


def _read_open_directory(root, expected_pin):
    _require(_names(root, 4) == {"export.json", "metadata.json", TEXT_PATH, "sources"},
             "FILESYSTEM_MEMBERSHIP")
    sources = os.open("sources", DIR_FLAGS, dir_fd=root)
    try:
        root_identity = _file_identity(os.fstat(root))
        source_information = os.fstat(sources)
        _require(stat.S_ISDIR(source_information.st_mode), "FILESYSTEM_TYPE")
        source_identity = _file_identity(source_information)
        _require(root_identity != source_identity, "FILESYSTEM_ALIAS")
        names = _names(sources, MAX_SOURCES)
        _require(1 <= len(names) <= MAX_SOURCES, "SOURCE_COUNT")
        seen = {root_identity, source_identity}
        result = _load_export(root, sources, expected_pin, names, seen)
        _require(_names(root, 4) == {"export.json", "metadata.json", TEXT_PATH, "sources"}
                 and _names(sources, MAX_SOURCES) == names, "FILESYSTEM_CHANGED")
        return result
    finally:
        os.close(sources)


def _os_error(error):
    codes = {errno.ENOENT: "FILESYSTEM_MISSING", errno.ELOOP: "FILESYSTEM_SYMLINK",
             errno.ENOTDIR: "FILESYSTEM_TYPE", errno.EACCES: "FILESYSTEM_ACCESS",
             errno.EPERM: "FILESYSTEM_ACCESS", errno.EEXIST: "OUTPUT_EXISTS",
             errno.ENAMETOOLONG: "PATH_BOUND", errno.ENOSPC: "FILESYSTEM_SPACE",
             errno.EMFILE: "RESOURCE_LIMIT", errno.ENFILE: "RESOURCE_LIMIT",
             errno.EFBIG: "ARTIFACT_SIZE"}
    return ExportReadError(codes.get(error.errno, "FILESYSTEM_IO"))


def read_export(directory, expected_export_sha256):
    """Return validated, inert data; all bytes are the ones actually checked.

    Keys: status, authority, manifest, sources, explanation_bytes,
    metadata_bytes, metadata, expected_export_sha256, claims.  Each ordered
    sources entry has id/path/bytes/sha256 and data (an exact bytes object).
    manifest and metadata are parsed, unverified producer assertions.  Refusal
    raises ExportReadError with a stable .code; this function writes no files.
    """
    try:
        _digest(expected_export_sha256)
        root = _open_directory(_path_parts(directory))
        try:
            return _read_open_directory(root, expected_export_sha256)
        finally:
            os.close(root)
    except OSError as error:
        raise _os_error(error) from None
    except (MemoryError, RecursionError, OverflowError):
        raise ExportReadError("RESOURCE_LIMIT") from None


def _limits():
    for kind, cap in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 60),
                      (resource.RLIMIT_FSIZE, MAX_BYTES)):
        soft, hard = resource.getrlimit(kind)
        new_hard = cap if hard == resource.RLIM_INFINITY else min(cap, hard)
        new_soft = new_hard if soft == resource.RLIM_INFINITY else min(new_hard, soft)
        try:
            resource.setrlimit(kind, (new_soft, new_hard))
        except (OSError, ValueError):
            raise ExportReadError("RESOURCE_LIMIT") from None
        actual_soft, actual_hard = resource.getrlimit(kind)
        _require(0 <= actual_soft <= actual_hard <= cap, "RESOURCE_LIMIT")


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        raise ExportReadError("CLI_USAGE")


def _arguments(arguments):
    _require(len(arguments) <= 8, "CLI_USAGE")
    _require(sum(_string_cost(item) for item in arguments) <= 16384, "CLI_USAGE")
    parser = _ArgumentParser(prog="read_transport_export.py", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "recover", "explanation", "metadata"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("export")
        if name != "inspect":
            command.add_argument("output")
        if name == "recover":
            command.add_argument("--source", required=True)
        command.add_argument("--expect-export-sha256", required=True)
    return parser.parse_args(arguments)


def _inspect(result):
    manifest = result["manifest"]
    roster = {item["path"]: item for item in manifest["files"]}
    return {"status": result["status"], "authority": "NONE",
            "package_identity": manifest["package_identity"],
            "expected_export_sha256": result["expected_export_sha256"],
            "schemas": {"export": manifest["schema"],
                        "metadata": result["metadata"]["schema"],
                        "explanation": manifest["explanation"]["schema"],
                        "runtime": manifest["runtime"]["schema"],
                        "base_decoder": manifest["runtime"]["base_decoder"]["schema"],
                        "decoder": manifest["runtime"]["base_decoder"]["decoder"]},
            "sources": _source_projection(manifest["sources"]),
            "explanation": dict(roster[TEXT_PATH]),
            "metadata": dict(roster["metadata.json"]), "claims": dict(CLAIMS),
            "assumptions": ["SHA256_COLLISION_RESISTANCE", "TRUSTED_PYTHON_AND_OS"],
            "concurrent_mutation": "NOT_FULLY_ISOLATED"}


def _selected(result, arguments):
    if arguments.command == "explanation":
        return result["explanation_bytes"], TEXT_PATH
    if arguments.command == "metadata":
        return result["metadata_bytes"], "metadata.json"
    _require(type(arguments.source) is str and
             SOURCE_ID.fullmatch(arguments.source) is not None, "SOURCE_ID")
    for item in result["sources"]:
        if item["id"] == arguments.source:
            return item["data"], item["id"]
    raise ExportReadError("SOURCE_NOT_FOUND")


def _receipt(result, raw, artifact):
    return {"status": "EXACT_PINNED_EXPORT_BYTES_RECOVERED", "authority": "NONE",
            "artifact": artifact, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "expected_export_sha256": result["expected_export_sha256"],
            "package_identity": result["manifest"]["package_identity"],
            "claims": dict(CLAIMS),
            "assumptions": ["SHA256_COLLISION_RESISTANCE", "TRUSTED_PYTHON_AND_OS"],
            "concurrent_mutation": "NOT_FULLY_ISOLATED"}


def _json_line(value):
    line = (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
    _require(len(line) <= MAX_BYTES, "STDOUT_BOUND")
    return line


def _write_bytes(descriptor, raw, error_code="OUTPUT_WRITE"):
    offset = 0
    for _ in range(len(raw) + 1):
        if offset == len(raw):
            return
        written = os.write(descriptor, raw[offset:])
        _require(type(written) is int and 0 < written <= len(raw) - offset,
                 error_code)
        offset += written
    raise ExportReadError(error_code)


def _remove_output(parent, name, identity):
    try:
        information = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    _require(_file_identity(information) == identity, "OUTPUT_CLEANUP_CHANGED")
    os.unlink(name, dir_fd=parent)


def _output_parent(path):
    try:
        spelling = os.fspath(path)
    except TypeError:
        raise ExportReadError("PATH_INVALID") from None
    _require(type(spelling) is str and not spelling.endswith(("/", "/.")) and
             spelling not in (".", ".."), "PATH_INVALID")
    parts = _path_parts(spelling)
    _require(bool(parts), "PATH_INVALID")
    return _open_directory(parts[:-1]), parts[-1]


def _publish(path, raw, line):
    parent, name = _output_parent(path)
    descriptor = None
    identity = None
    committed = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        information = os.fstat(descriptor)
        identity = _file_identity(information)
        _file_stat(information)
        _write_bytes(descriptor, raw)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        _file_stat(final)
        _require(final.st_size == len(raw), "OUTPUT_LENGTH")
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _file_stat(linked)
        _require(_file_identity(linked) == identity, "FILESYSTEM_CHANGED")
        closing = descriptor
        descriptor = None
        os.close(closing)
        _write_bytes(1, line, "STDOUT_WRITE")
        committed = True
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            try:
                if identity is not None and not committed:
                    _remove_output(parent, name, identity)
            finally:
                os.close(parent)


def _run(arguments):
    _limits()
    parsed = _arguments(arguments)
    result = read_export(parsed.export, parsed.expect_export_sha256)
    if parsed.command == "inspect":
        line = _json_line(_inspect(result))
        _write_bytes(1, line, "STDOUT_WRITE")
    else:
        raw, artifact = _selected(result, parsed)
        line = _json_line(_receipt(result, raw, artifact))
        _publish(parsed.output, raw, line)


def main(arguments=None):
    try:
        _run(sys.argv[1:] if arguments is None else arguments)
        return 0
    except ExportReadError as error:
        code = error.code
    except OSError as error:
        code = _os_error(error).code
    except (MemoryError, RecursionError, OverflowError):
        code = "RESOURCE_LIMIT"
    except KeyboardInterrupt:
        code = "INTERRUPTED"
    error_line = _json_line({"status": "REFUSED", "code": code, "authority": "NONE"})
    try:
        _write_bytes(2, error_line, "STDERR_WRITE")
    except (OSError, ExportReadError):
        # A failed diagnostic stream cannot be repaired through another sink.
        # Preserve refusal through the nonzero process exit status.
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
