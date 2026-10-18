// The only way the server touches files in its data folder. Reads refuse untrusted files; writes refuse untrusted
// folders and never follow symlinks (O_NOFOLLOW), so a hostile symlink can't redirect a root write.
const fs = require('fs');
const path = require('path');
const trust = require('./trust');

const C = fs.constants;

function read(file) {
  if (!trust.check(file).ok) return null;
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

function open(file, flags, mode) {
  if (!trust.check(file).ok) return null;
  try { fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 }); } catch {}
  if (!trust.check(file).ok) return null;
  try {
    const fd = fs.openSync(file, flags | C.O_NOFOLLOW, mode);
    const st = fs.fstatSync(fd);
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!st.isFile() || (uid !== null && st.uid !== uid && st.uid !== 0 && process.env.NETWATCH_UNSAFE_CONFIG !== '1')) { fs.closeSync(fd); return null; }
    return fd;
  } catch { return null; }
}

// Truncating happens only after the opened file is verified, never at open() time.
function write(file, data, mode = 0o644) {
  const fd = open(file, C.O_WRONLY | C.O_CREAT, mode);
  if (fd === null) return false;
  try { fs.ftruncateSync(fd, 0); fs.writeSync(fd, data); return true; } catch { return false; } finally { fs.closeSync(fd); }
}

function append(file, data) {
  const fd = open(file, C.O_WRONLY | C.O_CREAT | C.O_APPEND, 0o644);
  if (fd === null) return false;
  try { fs.writeSync(fd, data); return true; } catch { return false; } finally { fs.closeSync(fd); }
}

module.exports = { read, write, append };
