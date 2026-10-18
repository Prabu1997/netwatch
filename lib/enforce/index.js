// Picks the enforcement backend for this OS: iptables on Linux, pf on macOS.
const os = process.env.NETWATCH_PLATFORM || process.platform;
module.exports = os === 'darwin' ? require('./pf') : require('./iptables');
