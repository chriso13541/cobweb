#!/usr/bin/env bash
#
# update.sh - update a running cobweb install from its git checkout.
#
#   ./update.sh                 fetch, build, test, install, restart (asks first)
#   ./update.sh --check         show what's new upstream and what's installed; change nothing
#   ./update.sh --yes           don't ask for confirmation
#   ./update.sh --force         reinstall and restart even if the build is identical
#   ./update.sh --skip-tests    skip `go test` (build still has to succeed)
#   ./update.sh --help
#
# Run it as your normal user, NOT with sudo: git and go run as you, and sudo
# is used only for the steps that need root (backup, install, restart).
#
# What it does, in order - and it stops at the first thing that looks wrong,
# before anything installed has been touched:
#   1. refuses if the checkout has uncommitted changes or has diverged from origin
#   2. fetches, shows the incoming commits, and fast-forwards (never merges or rebases)
#   3. builds into a temp dir and runs the tests
#   4. if the result is byte-identical to what's installed, stops (no restart)
#   5. backs up config.json + credentials.json to <config dir>/backups/
#   6. keeps the old binary as <binary>.prev, swaps the new one in atomically
#   7. restarts the service and watches it for a few seconds
#   8. if it doesn't stay up: puts the old binary AND the old config.json back
#
# It never edits your config (other than restoring it on rollback), never
# touches nftables, and never updates the Go toolchain or your unit file.
#
# Restarting cobweb interrupts DNS and DHCP for a second or two. Existing
# connections, NAT and port forwards keep working, because the kernel does
# the forwarding. Leases survive in config.json.
#
# Overrides (env): COBWEB_BIN (/usr/local/bin/cobweb), COBWEB_CONFIG
# (/etc/cobweb/config.json), COBWEB_SERVICE (cobweb), COBWEB_SETTLE_SECS (8).

set -euo pipefail

BIN="${COBWEB_BIN:-/usr/local/bin/cobweb}"
CONFIG="${COBWEB_CONFIG:-/etc/cobweb/config.json}"
SERVICE="${COBWEB_SERVICE:-cobweb}"
SETTLE_SECS="${COBWEB_SETTLE_SECS:-8}"
KEEP_BACKUPS=10

CHECK_ONLY=0
ASSUME_YES=0
FORCE=0
SKIP_TESTS=0

say() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
	case "$arg" in
		--check) CHECK_ONLY=1 ;;
		-y | --yes) ASSUME_YES=1 ;;
		--force) FORCE=1 ;;
		--skip-tests) SKIP_TESTS=1 ;;
		-h | --help) usage; exit 0 ;;
		*) usage >&2; die "unknown option: $arg" ;;
	esac
done

# --- privileges -------------------------------------------------------------
if [ -n "${COBWEB_SUDO:-}" ]; then
	SUDO="$COBWEB_SUDO" # test hook
elif [ "$(id -u)" -eq 0 ]; then
	SUDO=""
else
	command -v sudo >/dev/null 2>&1 || die "not running as root and sudo isn't installed"
	SUDO="sudo"
fi

# --- init system ------------------------------------------------------------
INIT="${COBWEB_INIT:-}"
if [ -z "$INIT" ]; then
	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		INIT=systemd
	elif command -v rc-service >/dev/null 2>&1; then
		INIT=openrc
	else
		INIT=none
	fi
fi
if [ "$INIT" = systemd ] && ! systemctl cat "$SERVICE" >/dev/null 2>&1; then
	warn "no systemd unit named '$SERVICE' - the binary will be installed, but restart cobweb yourself"
	INIT=none
fi

svc_restart() {
	case "$INIT" in
		systemd) $SUDO systemctl restart "$SERVICE" ;;
		openrc) $SUDO rc-service "$SERVICE" restart ;;
		*) return 0 ;;
	esac
}
svc_stop() {
	case "$INIT" in
		systemd) $SUDO systemctl stop "$SERVICE" ;;
		openrc) $SUDO rc-service "$SERVICE" stop ;;
		*) return 0 ;;
	esac
}
svc_start() {
	case "$INIT" in
		systemd) $SUDO systemctl start "$SERVICE" ;;
		openrc) $SUDO rc-service "$SERVICE" start ;;
		*) return 0 ;;
	esac
}
# svc_healthy: true only if the service is up now and stays up for SETTLE_SECS.
# A bad binary under Restart=on-failure flaps between "active" and
# "activating (auto-restart)", so one look right after the restart proves
# nothing - this checks every second, and also fails on any automatic restart.
svc_healthy() {
	local i state base n
	case "$INIT" in
		systemd)
			base=$(systemctl show -p NRestarts --value "$SERVICE" 2>/dev/null || echo 0)
			for ((i = 0; i < SETTLE_SECS; i++)); do
				sleep 1
				state=$(systemctl show -p ActiveState --value "$SERVICE" 2>/dev/null || true)
				n=$(systemctl show -p NRestarts --value "$SERVICE" 2>/dev/null || echo 0)
				{ [ "$state" = active ] && [ "$n" = "$base" ]; } || return 1
			done
			;;
		openrc)
			for ((i = 0; i < SETTLE_SECS; i++)); do
				sleep 1
				$SUDO rc-service "$SERVICE" status >/dev/null 2>&1 || return 1
			done
			;;
		*) return 0 ;;
	esac
}
svc_logs() {
	case "$INIT" in
		systemd) $SUDO journalctl -u "$SERVICE" -n 15 --no-pager 2>/dev/null | sed 's/^/    /' || true ;;
		openrc) tail -n 15 /var/log/cobweb.log 2>/dev/null | sed 's/^/    /' || true ;;
	esac
}

installed_version() {
	if [ -x "$BIN" ]; then
		"$BIN" --version 2>/dev/null || echo "cobweb (built before --version existed)"
	else
		echo "(not installed at $BIN)"
	fi
}

# --- the checkout -----------------------------------------------------------
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
	|| die "$PWD isn't a git checkout - update.sh has to live inside the cloned cobweb repo"

BRANCH=$(git symbolic-ref --short -q HEAD || true)
[ -n "$BRANCH" ] || die "HEAD is detached; check out a branch first (git switch main)"

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	git status --short --untracked-files=no >&2
	die "you have uncommitted changes in this checkout (listed above). Commit or stash them, then re-run."
fi

UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
[ -n "$UPSTREAM" ] || UPSTREAM="origin/$BRANCH"

say "Fetching from origin..."
git fetch --quiet origin || die "git fetch failed - can this box reach GitHub?"
git rev-parse --verify --quiet "$UPSTREAM^{commit}" >/dev/null \
	|| die "can't find $UPSTREAM; set an upstream with: git branch -u origin/$BRANCH"

BEHIND=$(git rev-list --count "HEAD..$UPSTREAM")
AHEAD=$(git rev-list --count "$UPSTREAM..HEAD")
if [ "$BEHIND" -gt 0 ] && [ "$AHEAD" -gt 0 ]; then
	die "this checkout has $AHEAD local commit(s) AND origin has $BEHIND new one(s) - they've diverged. update.sh won't merge or rebase for you. Sort it out in git (e.g. git pull --rebase), then re-run."
fi

say "Checkout:  $BRANCH @ $(git rev-parse --short HEAD)  ($BEHIND behind, $AHEAD ahead of $UPSTREAM)"
say "Installed: $(installed_version)"
if [ "$BEHIND" -gt 0 ]; then
	say "Incoming commits:"
	git log --oneline --no-decorate "HEAD..$UPSTREAM" | sed 's/^/    /'
	git diff --stat "HEAD..$UPSTREAM" | tail -n 1 | sed 's/^/    /'
fi
if [ "$AHEAD" -gt 0 ]; then
	warn "$AHEAD local commit(s) aren't on origin yet; they will be built and installed as they are."
fi

if [ "$CHECK_ONLY" = 1 ]; then
	if [ "$BEHIND" -eq 0 ]; then say "Nothing new on origin."; else say "Run ./update.sh to apply."; fi
	exit 0
fi

CONFIRMED=0
confirm() {
	[ "$CONFIRMED" = 1 ] && return 0
	if [ "$ASSUME_YES" != 1 ]; then
		[ -t 0 ] || die "not running in a terminal; re-run with --yes to proceed without asking"
		local reply
		read -r -p "$1 [y/N] " reply
		case "$reply" in y | Y | yes | YES) ;; *) say "Cancelled; nothing was changed."; exit 0 ;; esac
	fi
	CONFIRMED=1
}

if [ "$BEHIND" -gt 0 ]; then
	confirm "Fast-forward to $(git rev-parse --short "$UPSTREAM"), build and install?"
	git merge --ff-only --quiet "$UPSTREAM"
	say "Checkout is now at $(git rev-parse --short HEAD)"
fi

# --- build + test (nothing installed is touched yet) ------------------------
if ! command -v go >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
	PATH="$PATH:/usr/local/go/bin"
fi
command -v go >/dev/null 2>&1 || die "Go isn't installed (or isn't on your PATH). cobweb is built from source; get Go from https://go.dev/dl/ and re-run."
NEED_GO=$(awk '/^go [0-9]/ { print $2; exit }' go.mod)
HAVE_GO=$(go env GOVERSION | sed 's/^go//')
if [ -n "$NEED_GO" ] && [ "$(printf '%s\n%s\n' "$HAVE_GO" "$NEED_GO" | sort -V | head -n 1)" != "$NEED_GO" ]; then
	die "this version of cobweb needs Go $NEED_GO or newer, but 'go' is $HAVE_GO. Install a newer Go from https://go.dev/dl/ (extract to /usr/local/go and put /usr/local/go/bin on your PATH), then re-run. Nothing installed was touched."
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
VERSION=$(git describe --tags --always --dirty)

if [ "$SKIP_TESTS" = 1 ]; then
	warn "skipping tests (--skip-tests)"
else
	say "Running tests..."
	go test ./... >"$WORK/test.log" 2>&1 || {
		tail -n 40 "$WORK/test.log" >&2
		die "tests failed, so nothing was installed - the running cobweb is untouched. (Checkout is at $(git rev-parse --short HEAD). --skip-tests overrides this if you know why.)"
	}
fi

say "Building $VERSION..."
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$WORK/cobweb" ./cmd/cobweb \
	|| die "build failed, so nothing was installed - the running cobweb is untouched."
"$WORK/cobweb" --version >/dev/null 2>&1 \
	|| die "the new binary won't even print its version, so it was not installed (wrong architecture?)"

if [ -x "$BIN" ] && [ "$FORCE" != 1 ] \
	&& [ "$(sha256sum <"$WORK/cobweb")" = "$(sha256sum <"$BIN")" ]; then
	say "Already running this exact build ($VERSION). Nothing to do."
	exit 0
fi

confirm "Install $VERSION and restart $SERVICE (DNS/DHCP pause for a second or two)?"

# --- install ----------------------------------------------------------------
[ -z "$SUDO" ] || $SUDO -v

CONFIG_DIR=$(dirname "$CONFIG")
BACKUP_DIR="$CONFIG_DIR/backups"
STAMP=$(date +%Y%m%d-%H%M%S)
CONFIG_BACKUP=""
if $SUDO test -f "$CONFIG"; then
	$SUDO install -d -m 0700 "$BACKUP_DIR"
	CONFIG_BACKUP="$BACKUP_DIR/config-$STAMP.json"
	$SUDO cp -p "$CONFIG" "$CONFIG_BACKUP"
	$SUDO chmod 600 "$CONFIG_BACKUP"
	if $SUDO test -f "$CONFIG_DIR/credentials.json"; then
		$SUDO cp -p "$CONFIG_DIR/credentials.json" "$BACKUP_DIR/credentials-$STAMP.json"
		$SUDO chmod 600 "$BACKUP_DIR/credentials-$STAMP.json"
	fi
	for kind in config credentials; do
		# shellcheck disable=SC2012
		$SUDO ls -1t "$BACKUP_DIR"/"$kind"-*.json 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" \
			| while read -r old; do $SUDO rm -f -- "$old"; done || true
	done
	say "Backed up config to $CONFIG_BACKUP"
else
	warn "no config at $CONFIG - skipping the config backup (first install?)"
fi

if [ "$INIT" = systemd ] && [ -f "init/systemd/cobweb.service" ] \
	&& [ -f "/etc/systemd/system/$SERVICE.service" ] \
	&& ! cmp -s init/systemd/cobweb.service "/etc/systemd/system/$SERVICE.service"; then
	warn "the repo's init/systemd/cobweb.service differs from /etc/systemd/system/$SERVICE.service. That's normal if you customised yours; update.sh never touches it. To compare: diff init/systemd/cobweb.service /etc/systemd/system/$SERVICE.service"
fi

HAD_BIN=0
OLD_VERSION=$(installed_version)
if [ -e "$BIN" ]; then
	HAD_BIN=1
	$SUDO cp -p "$BIN" "$BIN.prev"
fi
# Write beside the target, then rename over it. Overwriting a running
# executable in place fails with "Text file busy"; rename doesn't.
$SUDO install -m 0755 "$WORK/cobweb" "$BIN.new"
$SUDO mv -f "$BIN.new" "$BIN"
say "Installed $BIN"

rollback() {
	if [ "$HAD_BIN" != 1 ]; then
		warn "this was a first install, so there is no previous version to roll back to"
		return 1
	fi
	say "Rolling back to the previous build..."
	svc_stop || true
	$SUDO cp -p "$BIN.prev" "$BIN.new"
	$SUDO mv -f "$BIN.new" "$BIN"
	# A different version may have rewritten config.json (an older build
	# re-saving it drops fields it doesn't know about), so put it back too.
	if [ -n "$CONFIG_BACKUP" ]; then
		$SUDO cp -p "$CONFIG_BACKUP" "$CONFIG"
	fi
	svc_start || true
	if svc_healthy; then
		say "Rolled back. Running again: $(installed_version)"
	else
		warn "still not healthy after rolling back - look at the logs:"
		svc_logs
	fi
}

say "Restarting $SERVICE and watching it for ${SETTLE_SECS}s..."
if ! svc_restart; then
	warn "the restart command failed"
	rollback || true
	exit 1
fi
if ! svc_healthy; then
	warn "cobweb did not stay up after the restart. Its log:"
	svc_logs
	rollback || true
	exit 1
fi

say "Updated: $OLD_VERSION  ->  $(installed_version)"
[ "$HAD_BIN" != 1 ] || say "Previous binary kept at $BIN.prev"
[ -z "$CONFIG_BACKUP" ] || say "Config backup:   $CONFIG_BACKUP"
if [ "$HAD_BIN" = 1 ]; then
	say "To roll back by hand: sudo cp -p $BIN.prev $BIN && sudo systemctl restart $SERVICE"
	say "(an older build can drop settings it doesn't know about - restore the config backup too)"
fi
