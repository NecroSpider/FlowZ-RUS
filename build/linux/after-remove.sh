#!/bin/bash
# FlowZ deb postrm (electron-builder `deb.afterRemove`). electron-builder renders this file as a template:
# only the ${executable} / ${sanitizedProductName} macros below may use the dollar-brace form; plain shell
# variables must be written as $VAR (an unknown macro aborts the build).

# --- electron-builder default after-remove (kept verbatim: runs on every postrm call, as before) ---
# Delete the link to the binary
# update-alternatives --remove <name> <path>: 'path' must be the registered alternative binary,
# not the generic symlink — see https://man7.org/linux/man-pages/man1/update-alternatives.1.html
if type update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove '${executable}' '/opt/${sanitizedProductName}/${executable}'
else
    rm -f '/usr/bin/${executable}'
fi

APPARMOR_PROFILE_DEST='/etc/apparmor.d/${executable}'

# Remove and unload apparmor profile.
if [ -f "$APPARMOR_PROFILE_DEST" ]; then
  if apparmor_status --enabled > /dev/null 2>&1; then
    if ! { [ -x '/usr/bin/ischroot' ] && /usr/bin/ischroot; } && hash apparmor_parser 2>/dev/null; then
      apparmor_parser --remove "$APPARMOR_PROFILE_DEST" || true
    fi
  fi
  rm -f "$APPARMOR_PROFILE_DEST"
fi

# --- FlowZ privileged helper cleanup: only on a real removal, never on upgrade ---
# The helper lives outside the package (installed on demand by the app via pkexec), so dpkg does not know
# about it; without this `apt remove` leaves a root systemd service, its authorized-uids list and the
# resolve1 polkit rule behind. Paths mirror src/main/services/LinuxServiceHelper.ts.
case "$1" in
  remove|purge)
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now flowz-helper.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/flowz-helper.service
    rm -rf /usr/local/lib/flowz /var/lib/flowz /run/flowz
    rm -f /etc/polkit-1/rules.d/49-flowz-resolved.rules \
          /etc/polkit-1/localauthority/50-local.d/49-flowz-resolved.pkla
    if command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    ;;
esac

exit 0
