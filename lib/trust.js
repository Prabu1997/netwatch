// Is this file safe to believe, and safe to write? The server often runs as root but keeps its config in a folder an
// ordinary user owns. Anything that user (or malware running as them) can edit must not steer a root process:
// not the policy, not the blocklist, not the baseline, and not where root writes (a symlink would turn
// "append an alert" into "append to any file on the system").
// Rule: owner is the process's own uid (root: only root), and neither the file nor its folder is group/world-writable.
const fs = require('fs');
const path = require('path');

const problems = new Map(); // file -> reason, for the dashboard
const uidNow = () => (typeof process.getuid === 'function' ? process.getuid() : null);
const ownerOk = (st, uid) => (uid === 0 ? st.uid === 0 : st.uid === uid || st.uid === 0);
const looseMode = st => (st.mode & 0o022) !== 0;

function fixHint(file, uid = uidNow()) {
  const dir = path.dirname(file);
  return uid === 0 ? `sudo chown -R root "${dir}" && sudo chmod -R go-w "${dir}"` : `chmod -R go-w "${dir}"`;
}

// -> { ok, missing?, reason? }. `uid` is injectable for tests.
function check(file, { uid = uidNow(), allowMissing = true } = {}) {
  if (process.env.NETWATCH_UNSAFE_CONFIG === '1' || uid === null) return { ok: true, overridden: uid !== null };
  const dir = path.dirname(file);
  let verdict;
  try {
    const ds = fs.statSync(dir);
    if (!ds.isDirectory()) verdict = { ok: false, reason: `${dir} is not a directory` };
    else if (!ownerOk(ds, uid)) verdict = { ok: false, reason: `folder ${dir} is owned by uid ${ds.uid}, not ${uid === 0 ? 'root' : 'you'}` };
    else if (looseMode(ds)) verdict = { ok: false, reason: `folder ${dir} is writable by group/others (mode ${(ds.mode & 0o777).toString(8)})` };
  } catch (e) { verdict = e.code === 'ENOENT' ? { ok: true, missing: true } : { ok: false, reason: `cannot inspect ${dir}: ${e.code}` }; }
  if (!verdict) {
    try {
      const fs_ = fs.lstatSync(file);
      if (fs_.isSymbolicLink()) verdict = { ok: false, reason: `${file} is a symlink` };
      else if (!fs_.isFile()) verdict = { ok: false, reason: `${file} is not a regular file` };
      else if (!ownerOk(fs_, uid)) verdict = { ok: false, reason: `${file} is owned by uid ${fs_.uid}, not ${uid === 0 ? 'root' : 'you'}` };
      else if (looseMode(fs_)) verdict = { ok: false, reason: `${file} is writable by group/others (mode ${(fs_.mode & 0o777).toString(8)})` };
      else verdict = { ok: true };
    } catch (e) { verdict = e.code === 'ENOENT' ? (allowMissing ? { ok: true, missing: true } : { ok: false, reason: `${file} missing` }) : { ok: false, reason: `cannot inspect ${file}: ${e.code}` }; }
  }
  if (verdict.ok) problems.delete(file);
  else if (!problems.has(file) || problems.get(file).reason !== verdict.reason) {
    problems.set(file, { reason: verdict.reason, fix: fixHint(file, uid) });
    console.error(`untrusted config ignored: ${verdict.reason}\n  fix: ${fixHint(file, uid)}`);
  }
  return verdict;
}

module.exports = { check, problems: () => [...problems].map(([file, p]) => ({ file, reason: p.reason, fix: p.fix })) };
