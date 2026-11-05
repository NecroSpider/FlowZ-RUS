/** GitHub's release flag is authoritative; semver prerelease suffixes are also test builds. */
export function isPrereleaseVersion(version: string, flagged = false): boolean {
  return flagged || /^v?\d+\.\d+\.\d+-/.test(version);
}
