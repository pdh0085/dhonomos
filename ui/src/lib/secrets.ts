// Secret parameters, by name.

/** Name ends like this = secret -> value masked, typed as password, sent as secret. */
const SECRET = /(Password|Passphrase|PreSharedKey|KeyPassphrase|WEPKey|Secret)$/i;

export const isSecret = (path: string): boolean => SECRET.test(path);

/**
 * Last path segments of TR-181 write-only secrets (e.g.
 * `Device.WiFi.AccessPoint.{i}.Security.KeyPassphrase`, `Device.Users.User.{i}.Password`).
 * Get -> always empty string, whatever is set. Empty value is correct -> UI says device hides it,
 * no blank cell.
 * Keep list short + exact (names case-sensitive); every entry also matches `isSecret`.
 */
export const WRITE_ONLY_SECRETS: readonly string[] = [
	'KeyPassphrase',
	'SAEPassphrase',
	'PreSharedKey',
	'Password',
	'WEPKey',
	'RadiusSecret',
	'Secret'
];

export const isWriteOnlySecret = (path: string): boolean =>
	WRITE_ONLY_SECRETS.includes(path.slice(path.lastIndexOf('.') + 1));
