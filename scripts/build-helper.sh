#!/usr/bin/env bash
# 交叉编译 FlowZ 提权 helper（Go）：macOS（helper/，纯 stdlib，两 mac 架构）+ Windows（helper-win/，winio+x-sys，amd64）
# + Linux（helper-linux/，纯 stdlib，宿主架构）。
# 产物随 electron-builder extraResources（resources/mac-${arch} → mac；resources/win；resources/linux → linux）打进 app 包。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/helper"
OUT_NAME="com.flowz.helper"

if ! command -v go >/dev/null 2>&1; then
  if [ -n "${REQUIRE_HELPER:-}" ]; then
    echo "[build-helper] REQUIRE_HELPER is set but the Go toolchain was not found — the privileged helper is a required release component; aborting to avoid silently publishing a package without the helper" >&2
    exit 1
  fi
  echo "[build-helper] Go toolchain not found, skipping helper build (the privileged helper will not be bundled; at runtime the app falls back to the osascript watchdog script; release builds guarantee Go via setup-go)" >&2
  exit 0
fi

# Core trust (helper proto mac v10 / win v6 / linux v2): the SHA-256 of the bundled core (and libcronet where it is a
# separate file) is compiled into each helper. The privileged helper then accepts over its socket/pipe only that
# binary or ones an admin approved (trusted-hashes). Source of truth: src/shared/core-manifest.json — the same pins
# fetch-core / fetch-cronet verify. A helper without the pin would not enforce trust, so a missing pin is fatal.
MANIFEST="$ROOT/src/shared/core-manifest.json"
manifest_get() { # $1 = manifest field, $2 = platform key → lowercase hex on stdout, non-zero exit if absent/invalid
  node -e 'const m=require(process.argv[1]);const v=String(((m[process.argv[2]]||{})[process.argv[3]])||"").replace(/^sha256:/,"");if(!/^[0-9a-fA-F]{64}$/.test(v))process.exit(3);process.stdout.write(v.toLowerCase())' "$MANIFEST" "$1" "$2"
}
trust_ldflags() { # $1 = coreBinarySha256 key, $2 = cronetLibSha256 key ("" when cronet is linked into the core)
  local core cronet flags
  core="$(manifest_get coreBinarySha256 "$1")" || {
    echo "[build-helper] core-manifest.json has no valid coreBinarySha256[$1]; refusing to build a helper that cannot verify the core" >&2
    exit 1
  }
  flags="-X main.bundledCoreSHA256=$core"
  if [ -n "${2:-}" ]; then
    cronet="$(manifest_get cronetLibSha256 "$2")" || {
      echo "[build-helper] core-manifest.json has no valid cronetLibSha256[$2]; refusing to build" >&2
      exit 1
    }
    flags="$flags -X main.bundledCronetSHA256=$cronet"
  fi
  printf '%s' "$flags"
}

build() {
  local arch="$1" goarch="$2" trust
  local out="$ROOT/resources/mac-$arch/$OUT_NAME"
  trust="$(trust_ldflags "mac-$arch" "")"
  echo "[build-helper] mac-$arch ($goarch) → $out"
  ( cd "$SRC" && GOOS=darwin GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w $trust" -o "$out" . )
  chmod 755 "$out"
}

build arm64 arm64
build x64 amd64

# Windows 提权服务 helper（独立 module helper-win/，含 vendor/ → -mod=vendor 离线构建）。
# 输出到 resources/win/（与 sing-box.exe / libcronet.dll 同目录，对齐 ResourceManager.getWinHelperPath 与
# getPlatformResourceDir 的 win 分支）。GOOS=windows 从任意宿主交叉编译（纯 Go + winio/x-sys，CGO 关）。
WIN_SRC="$ROOT/helper-win"
if [ -d "$WIN_SRC" ]; then
  WIN_OUT="$ROOT/resources/win/com.flowz.helper.exe"
  WIN_TRUST="$(trust_ldflags win win)"
  echo "[build-helper] win-x64 (amd64) → $WIN_OUT"
  mkdir -p "$ROOT/resources/win"
  ( cd "$WIN_SRC" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
      go build -mod=vendor -trimpath -ldflags="-s -w $WIN_TRUST" -o "$WIN_OUT" . )
fi

# Linux 提权 helper（独立 module helper-linux/，纯 stdlib，需 linux-only syscall → 只在 GOOS=linux 编译）。输出到
# resources/linux/（与 sing-box / libcronet.so 同目录，对齐 ResourceManager.getLinuxHelperPath 与 getPlatformResourceDir
# 的 linux 分支；electron-builder 打包 resources/linux → linux）。按宿主架构本地编译；跨架构（arm64）随对应架构的发布
# 构建另行 GOARCH=arm64 交叉编译（AmbientCaps/SO_PEERCRED 为 linux 通用，无 CGO）。
LINUX_SRC="$ROOT/helper-linux"
if [ -d "$LINUX_SRC" ]; then
  LINUX_OUT="$ROOT/resources/linux/flowz-helper-linux"
  # 钉 amd64 匹配 package:linux/dist:linux 的 electron-builder --x64（否则 arm64 主机构建会打进不可执行的二进制）。
  # 纯 Go + linux-only syscall、无 CGO → 交叉编译零依赖；将来出 arm64 发布另加 GOARCH=arm64 腿即可。
  LINUX_GOARCH="${LINUX_GOARCH:-amd64}"
  # core-manifest pins only the amd64 Linux core ("linux"); other arches get no compiled pin (trust not enforced).
  LINUX_TRUST=""
  if [ "$LINUX_GOARCH" = "amd64" ]; then
    LINUX_TRUST="$(trust_ldflags linux linux)"
  else
    echo "[build-helper] WARNING: no core-manifest pin for linux/$LINUX_GOARCH; this helper will not enforce core trust" >&2
  fi
  echo "[build-helper] linux ($LINUX_GOARCH) → $LINUX_OUT"
  mkdir -p "$ROOT/resources/linux"
  ( cd "$LINUX_SRC" && GOOS=linux GOARCH="$LINUX_GOARCH" CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w $LINUX_TRUST" -o "$LINUX_OUT" . )
  chmod 755 "$LINUX_OUT"
fi
echo "[build-helper] done"
