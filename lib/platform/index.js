// Picks the OS backend. NETWATCH_PLATFORM overrides detection (used by tests).
const os = process.env.NETWATCH_PLATFORM || process.platform;
module.exports = os === 'darwin' ? require('./darwin') : require('./linux');
