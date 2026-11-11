import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, renameSync, statfsSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";
import { RotationError } from "./rotation-record.js";
import { ROTATION_MAX_TRUST_SNAPSHOT_BYTES } from "./rotation-trust-json.js";

const markerLimit = 128;

function refuse(code = "rotation_state_unavailable"): never {
  throw new RotationError(code);
}

function privateDirectory(path: string): void {
  if (process.platform !== "linux" || process.getuid === undefined || !isAbsolute(path) || normalize(path) !== path) refuse();
  const uid = process.getuid();
  const parent = dirname(path);
  for (let current = parent;; current = dirname(current)) {
    const value = lstatSync(current);
    if (!value.isDirectory() || value.isSymbolicLink() || (value.uid !== uid && value.uid !== 0)) refuse();
    if (current === parent && (value.uid !== uid || (value.mode & 0o777) !== 0o700)) refuse();
    if ((value.mode & 0o022) !== 0 && !((value.mode & 0o1000) !== 0 && value.uid === 0)) refuse();
    if (dirname(current) === current) break;
  }
  const type = BigInt.asUintN(32, statfsSync(parent, { bigint: true }).type);
  if (![0xef53n, 0x58465342n, 0x9123683en].includes(type)) refuse();
}

function checkFile(fd: number, maximum: number): number {
  const value = fstatSync(fd);
  if (process.getuid === undefined || !value.isFile() || value.uid !== process.getuid() ||
    (value.mode & 0o777) !== 0o600 || value.nlink !== 1 || !Number.isSafeInteger(value.size) || value.size < 1 || value.size > maximum) refuse();
  return value.size;
}

function readPrivate(path: string, maximum: number): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const size = checkFile(fd, maximum);
    const bytes = Buffer.alloc(size);
    let position = 0;
    while (position < size) {
      const count = readSync(fd, bytes, position, size - position, position);
      if (count === 0) refuse();
      position += count;
    }
    if (readSync(fd, Buffer.alloc(1), 0, 1, size) !== 0 || checkFile(fd, maximum) !== size) refuse();
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function syncDirectory(path: string): void {
  const fd = openSync(dirname(path), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeOwned(fd: number, bytes: Uint8Array): void {
  let position = 0;
  while (position < bytes.length) {
    const count = writeSync(fd, bytes, position, bytes.length - position, position);
    if (count === 0) refuse();
    position += count;
  }
  if (checkFile(fd, ROTATION_MAX_TRUST_SNAPSHOT_BYTES) !== bytes.length) refuse();
  fsyncSync(fd);
}

function bounded(bytes: Uint8Array): boolean {
  return bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= ROTATION_MAX_TRUST_SNAPSHOT_BYTES;
}

/** Внутренний cooperating-owner file profile; не ClockGuard, trust ACK или recovery. */
export class RotationFileOwner {
  private fenced = false;
  private closed = false;

  private constructor(private readonly path: string, private readonly marker: Buffer) {}

  private static acquire(path: string): RotationFileOwner {
    privateDirectory(path);
    const marker = Buffer.from(`mcp-jack/rotation-owner/v1\n${randomBytes(32).toString("base64url")}\n`, "ascii");
    const fd = openSync(path + ".owner", constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeOwned(fd, marker); } finally { closeSync(fd); }
    syncDirectory(path);
    return new RotationFileOwner(path, marker);
  }

  /** Только explicit unused creation; existing/uncertain artifacts не удаляются. */
  static initializeUnused(path: string, bytes: Uint8Array): void {
    const owner = this.createUnusedOwner(path, bytes);
    try { owner.close(); }
    catch { owner.fence(); refuse("rotation_state_unknown"); }
  }

  /** Higher store удерживает marker через dirty initialization и clock setup. */
  static createUnusedOwner(path: string, bytes: Uint8Array): RotationFileOwner {
    let owner: RotationFileOwner | undefined;
    let created = false;
    try {
      if (!bounded(bytes)) refuse();
      owner = this.acquire(path);
      const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      created = true;
      try { writeOwned(fd, bytes); } finally { closeSync(fd); }
      syncDirectory(path);
      return owner;
    } catch {
      if (owner !== undefined) {
        if (created) owner.fence();
        try { owner.close(); } catch { /* Unknown artifact остаётся fenced. */ }
      }
      refuse(created ? "rotation_state_unknown" : "rotation_state_unavailable");
    }
  }

  /** Noncreating open; stale markers не проверяются по PID и не ломаются автоматически. */
  static open(path: string): RotationFileOwner {
    let owner: RotationFileOwner | undefined;
    try {
      owner = this.acquire(path);
      owner.read();
      return owner;
    } catch {
      if (owner !== undefined) {
        try { owner.close(); } catch { /* Удаляется только подтверждённый собственный marker. */ }
      }
      return refuse();
    }
  }

  private ensure(): void {
    if (this.closed || this.fenced) refuse();
    try {
      privateDirectory(this.path);
      if (!readPrivate(this.path + ".owner", markerLimit).equals(this.marker)) refuse();
    } catch {
      this.fenced = true;
      refuse("rotation_state_unknown");
    }
  }

  read(): Uint8Array {
    this.ensure();
    try { return readPrivate(this.path, ROTATION_MAX_TRUST_SNAPSHOT_BYTES); }
    catch { return refuse(); }
  }

  /** Exact byte CAS для serialized owner; crypto/handler code не вызывается внутри. */
  replace(expected: Uint8Array, desired: Uint8Array): void {
    this.ensure();
    if (!bounded(expected) || !bounded(desired)) refuse();
    const before = Buffer.from(expected);
    const next = Buffer.from(desired);
    if (!Buffer.from(this.read()).equals(before)) refuse("rotation_state_changed");
    const temporary = join(dirname(this.path), `.${basename(this.path)}.${randomBytes(16).toString("hex")}.tmp`);
    try {
      const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { writeOwned(fd, next); } finally { closeSync(fd); }
      this.ensure();
      renameSync(temporary, this.path);
      syncDirectory(this.path);
    } catch {
      this.fenced = true;
      refuse("rotation_state_unknown");
    }
  }

  fence(): void { this.fenced = true; }

  /** Higher store обязан сначала drain/settle и подтвердить clean logical state. */
  close(): void {
    if (this.closed) return;
    this.ensure();
    try {
      unlinkSync(this.path + ".owner");
      syncDirectory(this.path);
      this.closed = true;
    } catch {
      this.fenced = true;
      refuse("rotation_state_unknown");
    }
  }
}
