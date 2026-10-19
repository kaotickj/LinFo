"""Host-specific management plans. Data only; never interpolate user input into a shell.

The separate, root-owned linfo-helper verifies the allowlists again before mutation.
"""
from __future__ import annotations
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
from typing import Callable

from .models import Finding

SUPPORTED_MANAGERS = ('apt', 'dnf', 'yum', 'zypper', 'pacman')


def parse_os_release(raw: str) -> dict[str, str]:
    result = {}
    for line in raw.splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            name, value = line.split('=', 1)
            if name.isidentifier():
                result[name] = value.strip().strip('"').strip("'")
    return result


@dataclass(frozen=True)
class SystemPlatform:
    name: str
    distro_id: str
    distro_like: tuple[str, ...]
    package_manager: str | None
    admin_group: str


def detect_platform(os_release: str | None = None, which: Callable[[str], str | None] = shutil.which) -> SystemPlatform:
    if os_release is None:
        try:
            os_release = Path('/etc/os-release').read_text(encoding='utf-8')
        except OSError:
            os_release = ''
    data = parse_os_release(os_release)
    distro_id = data.get('ID', 'unknown').lower()
    distro_like = tuple(data.get('ID_LIKE', '').lower().split())
    tokens = {distro_id, *distro_like}
    if tokens & {'debian', 'ubuntu', 'linuxmint', 'pop'}:
        candidates = ('apt',)
    elif tokens & {'fedora', 'rhel', 'centos', 'rocky', 'almalinux', 'ol'}:
        candidates = ('dnf', 'yum')
    elif tokens & {'opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'suse', 'sles'}:
        candidates = ('zypper',)
    elif tokens & {'arch', 'manjaro', 'endeavouros'}:
        candidates = ('pacman',)
    else:
        candidates = SUPPORTED_MANAGERS
    manager = next((cmd for cmd in candidates if which(cmd)), None)
    return SystemPlatform(data.get('PRETTY_NAME', distro_id), distro_id, distro_like, manager,
                          'sudo' if 'debian' in tokens or 'ubuntu' in tokens else 'wheel')


@dataclass(frozen=True)
class ManagementAction:
    label: str
    args: tuple[str, ...]
    category: str  # helper or editor
    risk: str = 'normal'
    explanation: str = ''


# The helper owns its own independent allowlist. These keys are not shell command names.
PACKAGE_BY_MANAGER = {
    'auditd': {'apt': 'auditd', 'dnf': 'audit', 'yum': 'audit', 'zypper': 'audit', 'pacman': 'audit'},
    'fail2ban': {m: 'fail2ban' for m in SUPPORTED_MANAGERS},
    'aide': {m: 'aide' for m in SUPPORTED_MANAGERS},
    'ssh_server': {'apt': 'openssh-server', 'dnf': 'openssh-server', 'yum': 'openssh-server',
                   'zypper': 'openssh', 'pacman': 'openssh'},
    'password_quality': {'apt': 'libpam-pwquality', 'dnf': 'libpwquality', 'yum': 'libpwquality',
                         'zypper': 'pam_pwquality', 'pacman': 'libpwquality'},
    'unattended': {'apt': 'unattended-upgrades', 'dnf': 'dnf-automatic', 'yum': 'dnf-automatic'},
    'ufw': {'apt': 'ufw', 'dnf': 'ufw', 'pacman': 'ufw'},
    'firewalld': {'apt': 'firewalld', 'dnf': 'firewalld', 'yum': 'firewalld',
                  'zypper': 'firewalld', 'pacman': 'firewalld'},
}

EDITABLE_CONFIGS = {
    'ssh': '/etc/ssh/sshd_config',
    'pam': '/etc/pam.d/common-password',
    'automatic': '/etc/apt/apt.conf.d/20auto-upgrades',
    'sysctl': '/etc/sysctl.d/99-zz-linfo-hardening.conf',
    'journal': '/etc/systemd/journald.conf',
    'sudoers': '/etc/sudoers',
    'ufw': '/etc/default/ufw',
    'firewalld': '/etc/firewalld/firewalld.conf',
}
SERVICE_ALLOWLIST = {'auditd.service', 'fail2ban.service', 'systemd-timesyncd.service',
                     'chrony.service', 'chronyd.service', 'telnet.socket', 'rsh.socket', 'rexec.socket'}


def _pkg(key: str, platform: SystemPlatform) -> ManagementAction | None:
    pkg = PACKAGE_BY_MANAGER.get(key, {}).get(platform.package_manager or '')
    return ManagementAction(f'Install {pkg}', ('package', 'install', key), 'helper', 'elevated',
                            'Installs packages using detected system package manager.') if pkg else None


def _service(name: str, operation: str) -> ManagementAction:
    return ManagementAction(f'{operation.capitalize()} {name}', ('service', operation, name), 'helper',
                            'elevated', 'Changes service enablement and runtime state.')


def _edit(key: str) -> ManagementAction:
    return ManagementAction('Edit ' + EDITABLE_CONFIGS[key], (EDITABLE_CONFIGS[key],), 'editor',
                            'elevated', 'Opens your chosen graphical editor through sudoedit.')


def actions_for(f: Finding, platform: SystemPlatform, installed: Callable[[str], bool] = lambda _: False) -> list[ManagementAction]:
    if f.status == 'PASS' and f.id not in {'svc.auditd.service', 'svc.fail2ban.service', 'system.systemd-timesyncd.service'}:
        return []
    actions: list[ManagementAction] = []
    if f.action_id in ('aslr', 'protected_links', 'ptrace', 'icmp_redirects', 'source_route'):
        actions.append(ManagementAction('Apply ' + f.title, ('apply', f.action_id), 'helper', 'elevated',
                                        'Creates a rollback receipt; may affect running workloads.'))
        actions.append(_edit('sysctl'))
    elif f.id in ('svc.auditd.service', 'svc.fail2ban.service'):
        service = f.id.removeprefix('svc.')
        package = 'auditd' if service == 'auditd.service' else 'fail2ban'
        if not installed(service.split('.')[0]):
            item = _pkg(package, platform)
            if item:
                actions.append(item)
        actions.append(_service(service, 'enable'))
        actions.append(_service(service, 'disable'))
    elif f.id.startswith('legacy.') and f.id.removeprefix('legacy.') in SERVICE_ALLOWLIST:
        if f.status in ('FAIL', 'WARN'):
            actions.append(_service(f.id.removeprefix('legacy.'), 'disable'))
    elif f.id == 'ssh.available':
        item = _pkg('ssh_server', platform)
        if item:
            actions.append(item)
        actions.append(_edit('ssh'))
    elif f.id.startswith('ssh.'):
        actions.append(_edit('ssh'))
    elif f.id == 'auth.pam_quality':
        item = _pkg('password_quality', platform)
        if item:
            actions.append(item)
        if platform.package_manager == 'apt':
            actions.append(_edit('pam'))
    elif f.id == 'package.automatic':
        item = _pkg('unattended', platform)
        if item:
            actions.append(item)
        if platform.package_manager == 'apt':
            actions.append(_edit('automatic'))
    elif f.id == 'monitor.aide':
        item = _pkg('aide', platform)
        if item:
            actions.append(item)
    elif f.id == 'network.firewall':
        firewall = 'ufw' if platform.package_manager == 'apt' else 'firewalld'
        item = _pkg(firewall, platform)
        if item:
            actions.append(item)
        # Do not enable a firewall before validating remote access rules.
    elif f.id == 'system.systemd-timesyncd.service':
        actions.append(_service('systemd-timesyncd.service', 'enable'))
        actions.append(_service('systemd-timesyncd.service', 'disable'))
    elif f.id == 'system.log_retention':
        actions.append(_edit('journal'))
    return actions


def available_editors(which: Callable[[str], str | None] = shutil.which) -> list[tuple[str, str]]:
    candidates = ['kate', 'mousepad', 'gedit', 'xed', 'kwrite', 'pluma', 'leafpad', 'subl']
    choices = [(name, path) for name in candidates if (path := which(name))]
    return choices


def editor_command(path: str, editor_path: str, which: Callable[[str], str | None] = shutil.which) -> tuple[list[str], dict[str, str]]:
    if path not in EDITABLE_CONFIGS.values():
        raise ValueError('Unsupported privileged configuration path')
    if not editor_path.startswith('/') or not os.path.exists(editor_path):
        raise ValueError('Editor must be installed at an absolute path')
    if not which('sudoedit'):
        raise RuntimeError('sudoedit is required. Configure administrative sudo/wheel permissions.')
    terminals = (
        ('konsole', ['-e']),
        ('xfce4-terminal', ['-x']),
        ('mate-terminal', ['--']),
        ('gnome-terminal', ['--']),
        ('xterm', ['-e']),
        ('x-terminal-emulator', ['-e']),
    )
    for terminal, flags in terminals:
        cmd = which(terminal)
        if cmd:
            env = dict(os.environ)
            env['SUDO_EDITOR'] = editor_path
            return [cmd, *flags, which('sudoedit'), path], env
    raise RuntimeError('No supported terminal emulator found for sudoedit')
