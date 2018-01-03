# shellcheck disable=SC2039

private_repo_url() {
    local repo_url="$1"
    local credentials="$2"
    local file="$3"

    echo "https://${credentials}@${repo_url}/ubuntu${file}"
}

package_version() {
    local package="$1"

    dpkg-query -W -f '${Version}\n' "$package" 2>/dev/null
}

apt_add_repo() {
    local repo_file="$1"
    local repo_url="$2"
    local credentials="$3"
    local keyring_file="$4"

    _apt_write_list_file "$repo_file" "$repo_url"
    _apt_add_auth "$repo_url" "$credentials"
    cp "$keyring_file" "$APT_KEYS_DIR"
}

apt_remove_repo() {
    local repo_file="$1"
    local repo_url="$2"
    local keyring_file="$3"

    rm -f "$repo_file" "$keyring_file"
    _apt_remove_auth "$repo_url"
}

apt_get() {
    DEBIAN_FRONTEND=noninteractive \
                   apt-get -y -o Dpkg::Options::='--force-confold' "$@"
}

is_package_installed() {
    local package="$1"

    dpkg-query -s "$package" >/dev/null 2>&1
}

# Install a package if the specified file doesn't exist
install_package_if_missing_file() {
    local file="$1"
    local package="$2"

    if [ ! -f "$file" ]; then
        echo -n "Installing missing dependency $package... "
        check_result apt_get install "$package"
    fi
}

_apt_write_list_file() {
    local repo_file="$1"
    local repo_url="$2"

    cat >"$repo_file" <<EOF
deb https://${repo_url}/ubuntu ${SERIES} main
# deb-src https://${repo_url}/ubuntu ${SERIES} main
EOF
}

_apt_add_auth() {
    local repo_host="$1"
    local credentials="$2"

    local login="${credentials%:*}"
    local password="${credentials#*:}"
    [ -f "$APT_AUTH_FILE" ] || touch "$APT_AUTH_FILE"
    chmod 600 "$APT_AUTH_FILE"
    echo "machine ${repo_host}/ubuntu/ login ${login} password ${password}" \
         >>"$APT_AUTH_FILE"
}

_apt_remove_auth() {
    local repo_host="$1"

    # shellcheck disable=SC1117
    sed -i "/^machine ${repo_host}\/ubuntu\/ login/d" "$APT_AUTH_FILE"
}
