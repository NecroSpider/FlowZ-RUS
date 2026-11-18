export type AppUpdateChannel = 'stable' | 'prerelease';

export function normalizeAppUpdateChannel(value: unknown): AppUpdateChannel {
  return value === 'prerelease' ? 'prerelease' : 'stable';
}

/** GitHub's release flag is authoritative; semver prerelease suffixes are also test builds. */
export function isPrereleaseVersion(version: string, flagged = false): boolean {
  return flagged || /^v?\d+\.\d+\.\d+-/.test(version);
}
