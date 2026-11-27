#!/usr/bin/env python3
"""Read-only browser metadata audit. Never queries cookie contents or history.

Output is PRIVATE: extension IDs and profile locations can identify installed tools.
No network, dependencies, browser launches, credential stores, or database copies.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from urllib.parse import urlparse
from audit_io import is_redirected

SENSITIVE = {'cookies', 'debugger', 'nativeMessaging', 'management', 'webRequest',
             'webRequestBlocking', 'clipboardRead', 'history', 'proxy',
             'privacy', 'contentSettings'}
BROAD = {'<all_urls>', '*://*/*', 'http://*/*', 'https://*/*', 'file:///*'}
PREF_KEYS = [('safebrowsing', 'enabled'), ('safebrowsing', 'enhanced'),
             ('profile', 'block_third_party_cookies'), ('profile', 'cookie_controls_mode'),
             ('profile', 'default_content_setting_values', 'cookies'),
             ('extensions', 'ui', 'developer_mode'), ('https_only_mode_enabled',)]
COOKIE_COLUMNS = {'is_secure', 'is_httponly', 'samesite', 'expires_utc',
                  'has_expires', 'is_persistent', 'isSecure', 'isHttpOnly',
                  'sameSite', 'expiry'}


def safe_text(value, limit=180):
    return re.sub(r'[\x00-\x1f\x7f]', '', str(value))[:limit]


def linked_path(path):
    """Do not allow a nested symlink to redirect an audit into unrelated files."""
    try:
        return is_redirected(path)
    except (OSError, RuntimeError):
        return True


def read_json(path, limit=24 * 1024 * 1024):
    if linked_path(path):
        return None, 'symlink_not_followed'
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return None, 'nonregular_file_skipped'
        if path.stat().st_size > limit:
            return None, 'size_limit'
        with path.open('r', encoding='utf-8') as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, 'absent'
    except (OSError, ValueError) as e:
        return None, type(e).__name__


def nested(data, keys):
    cur = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def sqlite_source_snapshot(path):
    """Inspect source metadata without opening SQLite or creating any sidecar."""
    snapshot = {}
    for suffix in ('', '-wal', '-shm', '-journal'):
        item = Path(str(path) + suffix)
        if linked_path(item):
            raise ValueError('symlink')
        try:
            info = item.stat()
        except FileNotFoundError:
            snapshot[suffix] = None
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('not_regular_file')
        snapshot[suffix] = (info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns)
    return snapshot


def cookie_stats(path, browser):
    try:
        before = sqlite_source_snapshot(path)
    except ValueError as e:
        return {'status': 'skipped_symlink' if str(e) == 'symlink' else 'skipped_nonregular_file'}
    except OSError as e:
        return {'status': 'unavailable', 'error_type': type(e).__name__}
    if before[''] is None:
        return {'status': 'not_present'}
    # Even mode=ro may create a missing SHM beside a live WAL database. Never
    # connect in this state. Do not stop a browser, checkpoint, copy, or delete.
    if ((before['-wal'] is not None and before['-wal'][2] > 0)
            or (before['-journal'] is not None and before['-journal'][2] > 0)):
        return {'status': 'live_database_requires_closed_browser',
                'reason': 'nonempty_wal_or_rollback_journal_present; no SQLite connection made; actual writer activity unknown',
                'action': 'User may close the browser and rerun; do not close it automatically or remove sidecars. A persistent sidecar alone does not prove active writing.'}
    result = _cookie_stats_immutable(path, browser)
    try:
        after = sqlite_source_snapshot(path)
    except (OSError, ValueError):
        return {'status': 'inconsistent_discarded', 'reason': 'source_unavailable_or_redirected_after_read'}
    if before != after:
        return {'status': 'inconsistent_discarded', 'reason': 'database_or_sidecar_metadata_changed_during_read'}
    return result


def _cookie_stats_immutable(path, browser):
    """Only called after guarding WAL/journal; caller discards unstable results."""
    table = 'moz_cookies' if browser == 'Firefox' else 'cookies'
    conn = None
    try:
        # immutable avoids locking and source sidecar writes. It would ignore
        # live WAL changes, so the caller guards and rechecks every source file.
        conn = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
        conn.execute('PRAGMA query_only=ON')

        def authorizer(action, arg1, arg2, db, trigger):
            if action == sqlite3.SQLITE_READ:
                if arg1 == table and (arg2 in COOKIE_COLUMNS or arg2 == ''):
                    return sqlite3.SQLITE_OK
                if arg1 == 'sqlite_master':
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION):
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and arg1 == 'table_info' and arg2 == table:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        conn.set_authorizer(authorizer)
        cols = {row[1] for row in conn.execute('PRAGMA table_info(' + table + ')')}
        if not cols:
            return {'status': 'unsupported_schema'}
        expressions = ['COUNT(*)']
        names = ['total']
        for key, name in [('is_secure', 'without_secure'), ('is_httponly', 'without_httponly'),
                          ('isSecure', 'without_secure'), ('isHttpOnly', 'without_httponly')]:
            if key in cols:
                expressions.append('SUM(CASE WHEN "' + key + '"=0 THEN 1 ELSE 0 END)')
                names.append(name)
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        if 'expires_utc' in cols:
            now_units = int((now + 11644473600) * 1000000)
            expiry = 'expires_utc'
            future = now_units + 365 * 86400 * 1000000
        elif 'expiry' in cols:
            now_units, expiry = int(now), 'expiry'
            future = now_units + 365 * 86400
        else:
            expiry = None
        if expiry:
            expressions.extend([
                'SUM(CASE WHEN "' + expiry + '">0 AND "' + expiry + '"<' + str(now_units) + ' THEN 1 ELSE 0 END)',
                'SUM(CASE WHEN "' + expiry + '">' + str(future) + ' THEN 1 ELSE 0 END)'])
            names.extend(['expired_rows', 'expires_more_than_365_days_from_now'])
        row = conn.execute('SELECT ' + ','.join(expressions) + ' FROM ' + table).fetchone()
        result = {'status': 'read_only_ok', 'access_mode': 'immutable_guarded',
                  **dict(zip(names, [int(x or 0) for x in row]))}
        same = 'samesite' if 'samesite' in cols else 'sameSite' if 'sameSite' in cols else None
        if same:
            result['samesite_raw_counts'] = {str(a): int(b) for a, b in conn.execute(
                'SELECT "' + same + '",COUNT(*) FROM ' + table + ' GROUP BY "' + same + '"')}
        result['interpretation'] = ('Metadata only. Missing Secure/HttpOnly or long expiry does not prove compromise; '
                                    'cookie purpose is unknown. SameSite integers are browser-specific. '
                                    'Third-party status cannot be inferred from this aggregate.')
        return result
    except (OSError, sqlite3.Error) as e:
        return {'status': 'unavailable', 'error_type': type(e).__name__}
    finally:
        if conn is not None:
            conn.close()


def extension_info(ext_id, settings, manifest=None):
    manifest = manifest or settings.get('manifest') or {}
    if not isinstance(manifest, dict):
        manifest = {}
    permissions = manifest.get('permissions', [])
    permissions = permissions if isinstance(permissions, list) else []
    hosts = manifest.get('host_permissions', [])
    hosts = hosts if isinstance(hosts, list) else []
    content_matches = []
    for item in manifest.get('content_scripts', []) if isinstance(manifest.get('content_scripts', []), list) else []:
        if isinstance(item, dict):
            content_matches.extend(item.get('matches', []) if isinstance(item.get('matches', []), list) else [])
    active = settings.get('active_permissions', {})
    active = active if isinstance(active, dict) else {}
    granted_api = active.get('api', [])
    granted_api = granted_api if isinstance(granted_api, list) else []
    state = settings.get('state')
    loc = settings.get('location')
    from_store = settings.get('from_webstore')
    component = loc in (5, 10)
    url = manifest.get('update_url')
    try:
        host = urlparse(url).hostname if isinstance(url, str) else None
    except ValueError:
        host = None
    output = {
        'id': safe_text(ext_id), 'name_untrusted': safe_text(manifest.get('name', 'unknown')),
        'version': safe_text(manifest.get('version', 'unknown')),
        'enabled': True if state == 1 else False if state in (0, 2) else None,
        'state_raw': state if isinstance(state, (int, bool)) else None,
        'component': component, 'location_raw': loc if isinstance(loc, int) else None,
        'from_webstore': from_store if isinstance(from_store, bool) else None,
        'update_domain': safe_text(host) if host else None,
        'requested_sensitive_permissions': sorted(set(x for x in permissions if isinstance(x, str)) & SENSITIVE),
        'granted_sensitive_permissions': sorted(set(x for x in granted_api if isinstance(x, str)) & SENSITIVE),
        'broad_requested_hosts': sorted(set(x for x in permissions + hosts + content_matches if isinstance(x, str)) & BROAD),
        'optional_permissions_count': len(manifest.get('optional_permissions', [])) if isinstance(manifest.get('optional_permissions', []), list) else 0,
        'review_flags': []}
    if not component:
        if loc in (4, 8):
            output['review_flags'].append('unpacked_or_command_line_source')
        elif from_store is False:
            output['review_flags'].append('store_origin_not_established')
        if output['requested_sensitive_permissions'] or output['broad_requested_hosts']:
            output['review_flags'].append('broad_or_sensitive_requested_permissions')
    return output


def localize_manifest_name(manifest, version_dir):
    """Resolve a packaged display label only; never run extension code."""
    manifest = dict(manifest)
    match = re.fullmatch(r'__MSG_([A-Za-z0-9_@]+)__', str(manifest.get('name', '')))
    if not match:
        return manifest
    locale = manifest.get('default_locale', 'en')
    candidates = [locale, 'en', 'en_US', 'zh_TW']
    for candidate in candidates:
        if not isinstance(candidate, str) or not re.fullmatch(r'[A-Za-z0-9_@-]+', candidate):
            continue
        messages, error = read_json(version_dir / '_locales' / candidate / 'messages.json', 2 * 1024 * 1024)
        if not isinstance(messages, dict):
            continue
        item = next((v for k, v in messages.items() if k.lower() == match.group(1).lower()), None)
        if isinstance(item, dict) and isinstance(item.get('message'), str):
            manifest['name'] = safe_text(item['message'])
            break
    return manifest


def chromium_profile(profile, browser, root, profile_label=None):
    pref, pref_error = read_json(profile / 'Preferences')
    pref = pref if isinstance(pref, dict) else {}
    prefs = {}
    for key in PREF_KEYS:
        val = nested(pref, key)
        prefs['.'.join(key)] = val if isinstance(val, (bool, int, float)) else 'not_explicitly_stored_or_unavailable'
    ext_settings = nested(pref, ('extensions', 'settings'))
    ext_settings = ext_settings if isinstance(ext_settings, dict) else {}
    extensions = {}
    for ext_id, item in ext_settings.items():
        if not re.fullmatch('[a-p]{32}', ext_id) or not isinstance(item, dict):
            continue
        extensions[ext_id] = extension_info(ext_id, item)
    # Secure Preferences contains extension state on some Chromium versions. Do not
    # open it: inventory manifests instead and explicitly leave activation unknown.
    folder = profile / 'Extensions'
    if folder.is_dir() and not linked_path(folder):
        for ext_dir in sorted(folder.iterdir()):
            if linked_path(ext_dir) or not ext_dir.is_dir() or not re.fullmatch('[a-p]{32}', ext_dir.name):
                continue
            versions = [p for p in ext_dir.iterdir() if p.is_dir() and not linked_path(p)]
            # More than one version can remain after updates; newest mtime is only an inventory candidate.
            versions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            if not versions:
                continue
            manifest, err = read_json(versions[0] / 'manifest.json', 2 * 1024 * 1024)
            if isinstance(manifest, dict):
                manifest = localize_manifest_name(manifest, versions[0])
                if ext_dir.name not in extensions:
                    extensions[ext_dir.name] = extension_info(ext_dir.name, {}, manifest)
                    extensions[ext_dir.name]['activation_note'] = 'manifest_on_disk; enabled state unavailable'
                elif extensions[ext_dir.name]['name_untrusted'] == 'unknown':
                    extensions[ext_dir.name] = extension_info(ext_dir.name, ext_settings.get(ext_dir.name, {}), manifest)
                extensions[ext_dir.name]['versions_on_disk'] = len(versions)
                if str(extensions[ext_dir.name]['name_untrusted']).startswith('__MSG_'):
                    extensions[ext_dir.name]['name_untrusted'] = safe_text(manifest.get('name', 'unknown'))
    cookie_path = profile / 'Network' / 'Cookies'
    if not cookie_path.exists():
        cookie_path = profile / 'Cookies'
    return {'browser': browser, 'profile': profile_label or str(profile.relative_to(root)),
            'preferences_status': pref_error or 'read_whitelisted_fields',
            'security_preferences': prefs, 'cookies': cookie_stats(cookie_path, browser),
            'extensions': list(extensions.values())}


def firefox_profile(profile, root):
    prefs = {}
    pref_status = 'absent'
    pref_readable = None
    pref_limit = 8 * 1024 * 1024
    allowed = {'browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled',
               'network.cookie.cookieBehavior', 'privacy.trackingprotection.enabled',
               'dom.security.https_only_mode', 'xpinstall.signatures.required'}
    path = profile / 'prefs.js'
    try:
        if linked_path(path):
            pref_status = 'symlink_not_followed'
        elif not path.exists():
            pref_status = 'absent'
        elif not stat.S_ISREG(path.stat().st_mode):
            pref_status = 'nonregular_file_skipped'
        elif path.stat().st_size > pref_limit:
            pref_status = 'size_limit'
        else:
            with path.open(encoding='utf-8') as fh:
                for line in fh:
                    match = re.match(r'user_pref\("([a-zA-Z0-9_.]+)",\s*(true|false|-?\d+)\);', line)
                    if match and match.group(1) in allowed:
                        prefs[match.group(1)] = json.loads(match.group(2))
            pref_status = 'read_whitelisted_fields'
            pref_readable = True
    except (OSError, UnicodeError) as e:
        pref_status = type(e).__name__
        pref_readable = False
        prefs = {}  # Do not report an incomplete parse as authoritative settings.
    data, error = read_json(profile / 'extensions.json')
    extensions = []
    for item in (data or {}).get('addons', []) if isinstance(data, dict) else []:
        if not isinstance(item, dict) or item.get('type') != 'extension':
            continue
        perms = item.get('userPermissions') or {}
        perms = perms if isinstance(perms, dict) else {}
        api = perms.get('permissions', [])
        api = api if isinstance(api, list) else []
        hosts = perms.get('origins', [])
        hosts = hosts if isinstance(hosts, list) else []
        locale = item.get('defaultLocale') or {}
        locale = locale if isinstance(locale, dict) else {}
        extensions.append({'id': safe_text(item.get('id', 'unknown')),
                           'name_untrusted': safe_text(locale.get('name', 'unknown')),
                           'version': safe_text(item.get('version', 'unknown')),
                           'enabled': item.get('active') if isinstance(item.get('active'), bool) else None,
                           'signed_state_raw': item.get('signedState') if isinstance(item.get('signedState'), int) else None,
                           'requested_sensitive_permissions': sorted(set(x for x in api if isinstance(x, str)) & SENSITIVE),
                           'broad_requested_hosts': sorted(set(x for x in hosts if isinstance(x, str)) & BROAD),
                           'review_flags': ['broad_or_sensitive_requested_permissions'] if set(x for x in api if isinstance(x, str)) & SENSITIVE or set(x for x in hosts if isinstance(x, str)) & BROAD else []})
    return {'browser': 'Firefox', 'profile': str(profile.relative_to(root)),
            'preferences_status': pref_status, 'preferences_source_readable': pref_readable,
            'preferences_byte_limit': pref_limit,
            'security_preferences': prefs, 'cookies': cookie_stats(profile / 'cookies.sqlite', 'Firefox'),
            'extensions_status': error or 'read_metadata', 'extensions': extensions}


def browser_roots(home):
    roots = [('Chrome', home / 'Library/Application Support/Google/Chrome'),
             ('Edge', home / 'Library/Application Support/Microsoft Edge'),
             ('Brave', home / 'Library/Application Support/BraveSoftware/Brave-Browser'),
             ('Atlas', home / 'Library/Application Support/com.openai.atlas/browser-data/host'),
             ('Chrome', home / '.config/google-chrome'), ('Chromium', home / '.config/chromium'),
             ('Edge', home / '.config/microsoft-edge'), ('Brave', home / '.config/BraveSoftware/Brave-Browser'),
             ('Chrome', home / 'AppData/Local/Google/Chrome/User Data'),
             ('Edge', home / 'AppData/Local/Microsoft/Edge/User Data'),
             ('Brave', home / 'AppData/Local/BraveSoftware/Brave-Browser/User Data')]
    return roots


def audit(home):
    result = {'schema_version': 1, 'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'mode': 'read_only_metadata', 'profiles': [], 'coverage': [], 'errors': [],
              'privacy': ['No cookie values, encrypted values, hostnames, names, browser history, passwords, '
                          'keychains, Local Storage, or credential databases queried.',
                          'Only whitelisted preference values and extension metadata are retained.',
                          'No network requests, live database copies, browser launches, or setting changes.'],
              'limitations': ['Local files may not reflect unsaved settings or policy overrides; omitted preferences do not imply disabled protection.',
                              'An extension manifest on disk does not prove the extension is active; permissions are requested scope, not proof of abuse.',
                              'Newest extension version by modification time is an inventory candidate, not proof of the loaded version.',
                              'Cookie aggregates cannot identify stolen sessions, malicious sites, third-party status, or active exfiltration.',
                              'Cookie databases with nonempty WAL or any rollback journal are skipped without opening SQLite. Stable sources use immutable mode; changed source metadata causes results to be discarded. Never close browsers or remove sidecars automatically.',
                              'Safari binary cookie stores are intentionally not opened; Safari settings/extensions require a separate read-only UI check.']}
    def scan_root(browser, root):
        coverage = {'browser': browser, 'root_relative_to_home': str(root.relative_to(home)),
                    'discovered_profiles': 0, 'processed_profiles': 0, 'complete_profiles': 0,
                    'profile_count': 0, 'status': 'complete'}
        try:
            if not root.exists():
                return
            if linked_path(root):
                coverage['status'] = 'symlink_root_skipped'
                result['coverage'].append(coverage)
                result['errors'].append({'browser': browser, 'stage': 'root_discovery', 'error_type': 'symlink_root_skipped'})
                return
            if not root.is_dir():
                return
            children = sorted(root.iterdir())
        except OSError as e:
            coverage.update(status='unavailable', discovered_profiles=None, profile_count=None)
            result['coverage'].append(coverage)
            result['errors'].append({'browser': browser, 'stage': 'root_discovery', 'error_type': type(e).__name__})
            return
        profiles = []
        for number, child in enumerate(children, 1):
            try:
                if not child.is_dir() or linked_path(child):
                    continue
                if browser == 'Firefox':
                    candidate = (child / 'prefs.js').is_file() or (child / 'cookies.sqlite').is_file()
                else:
                    candidate = child.name == 'Default' or re.fullmatch(r'Profile \d+', child.name) or (child / 'Preferences').is_file()
                if candidate:
                    profiles.append(child)
            except OSError as e:
                coverage['status'] = 'partial'
                result['errors'].append({'browser': browser, 'stage': 'profile_discovery',
                                         'directory_index': number, 'error_type': type(e).__name__})
        coverage['discovered_profiles'] = coverage['profile_count'] = len(profiles)
        for number, profile in enumerate(profiles, 1):
            label = profile.name if profile.name == 'Default' or re.fullmatch(r'Profile \d+', profile.name) else 'custom-profile-' + str(number)
            try:
                row = firefox_profile(profile, root) if browser == 'Firefox' else chromium_profile(profile, browser, root, label)
            except (OSError, ValueError, TypeError) as e:
                row = {'browser': browser, 'profile': label, 'profile_status': 'unavailable',
                       'preferences_status': 'not_collected_due_to_profile_error',
                       'security_preferences': {}, 'cookies': {'status': 'not_collected_due_to_profile_error'},
                       'extensions_status': 'not_collected_due_to_profile_error', 'extensions': [],
                       'errors': [{'stage': 'profile_collection', 'error_type': type(e).__name__}]}
            coverage['processed_profiles'] += 1
            gaps = list(row.get('errors', []))
            if row.get('preferences_status') not in ('read_whitelisted_fields', 'absent'):
                gaps.append({'stage': 'preferences', 'status': row.get('preferences_status', 'unknown')})
            if row['cookies']['status'] not in ('read_only_ok', 'not_present'):
                gaps.append({'stage': 'cookies', 'status': row['cookies']['status']})
            if row.get('extensions_status', 'read_metadata') not in ('read_metadata', 'absent'):
                gaps.append({'stage': 'extensions', 'status': row['extensions_status']})
            row['coverage_gaps'] = gaps
            row['coverage_status'] = 'partial' if gaps else 'complete'
            if gaps:
                coverage['status'] = 'partial'
                result['errors'].append({'browser': browser, 'profile': row['profile'], 'coverage_gaps': gaps})
            else:
                coverage['complete_profiles'] += 1
            result['profiles'].append(row)
        result['coverage'].append(coverage)

    for browser, root in browser_roots(home):
        scan_root(browser, root)
    for root in [home / 'Library/Application Support/Firefox/Profiles', home / '.mozilla/firefox', home / 'AppData/Roaming/Mozilla/Firefox/Profiles']:
        scan_root('Firefox', root)
    result['coverage'].append({'browser': 'Safari', 'status': 'not_inspected_binary_cookie_store'})
    result['coverage_status'] = 'partial' if result['errors'] else 'complete'
    result['coverage_totals'] = {
        'discovered_profiles': sum(c.get('discovered_profiles') or 0 for c in result['coverage']),
        'processed_profiles': sum(c.get('processed_profiles', 0) for c in result['coverage']),
        'complete_profiles': sum(c.get('complete_profiles', 0) for c in result['coverage']),
        'unreadable_roots': sum(c.get('status') == 'unavailable' for c in result['coverage'])}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = audit(args.home.expanduser().absolute())
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Do not overwrite a symlink or existing artifact by accident.
    fd = os.open(str(args.output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write('\n')
    print(json.dumps({'output': str(args.output), 'profiles': len(data['profiles']),
                      'coverage_status': data['coverage_status'],
                      'coverage_totals': data['coverage_totals'],
                      'cookie_databases_read': sum(p['cookies']['status'] == 'read_only_ok' for p in data['profiles']),
                      'extension_entries': sum(len(p['extensions']) for p in data['profiles'])}, ensure_ascii=False))


if __name__ == '__main__':
    main()
