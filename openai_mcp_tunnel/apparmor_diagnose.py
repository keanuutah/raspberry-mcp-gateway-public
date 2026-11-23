"""Read-only AppArmor diagnostic for the MCP gateway process.

Reads kernel state and bundled policy text only. Does not execute external
commands, write, toggle confinement, or attempt forbidden operations.
"""
from pathlib import Path
import re

# HAOS Supervisor loads the local add-on under the local_ prefixed profile.
PROFILE = 'local_openai_mcp_tunnel'
MAX_READ = 256 * 1024

def _read(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as stream:
            return stream.read(MAX_READ + 1)[:MAX_READ], None
    except (OSError, ValueError) as exc:
        return None, type(exc).__name__

def _mode(text):
    if text is None:
        return 'unavailable'
    if text.strip() == 'unconfined':
        return 'unconfined'
    matches = re.findall(r'\((enforce|complain|kill|unconfined)\)', text, re.I)
    return matches[-1].lower() if matches else 'unknown'

def _label(text):
    if text is None:
        return None
    value = text.strip()
    # Do not expose other unrelated labels or potentially sensitive paths.
    return PROFILE if re.search(r'(?<![\w.-])'+re.escape(PROFILE)+r'(?![\w.-])',value) else None

def _policy_checks(contents):
    if contents is None:
        return {'available':False,'all_required_rules_present':None}
    lines={line.strip() for line in contents.splitlines() if not line.lstrip().startswith('#')}
    required={
        'options_read_only': ('/data/options.json r,' in lines and 'deny /data/options.json w,' in lines),
        'backup_exact_extension': '/homeassistant_config/yaml_backups/*.yaml.bak rwk,' in lines,
        'quarantine_scoped': '/homeassistant_config/yaml_backups/.gw14-quarantine-*/* rwk,' in lines,
        'quarantine_directory': '/homeassistant_config/yaml_backups/.gw14-quarantine-*/ rw,' in lines,
        'package_write_direct_children': '/homeassistant_config/packages/* rwk,' in lines,
        'no_recursive_backup_write': not any(re.match(r'^/homeassistant_config/yaml_backups/\*\*\s+rw',x) for x in lines),
        'no_generic_backup_child_write': '/homeassistant_config/yaml_backups/* rwk,' not in lines,
        'no_generic_ha_recursive_write': not any(re.match(r'^/homeassistant_config/\*\*\s+rw',x) for x in lines),
    }
    return {'available':True,'checks':required,'all_required_rules_present':all(required.values()),
            'warning':'Bundled policy inspection is NOT proof of the loaded kernel policy.'}

def diagnose(proc_current='/proc/self/attr/current', proc_init='/proc/1/attr/current',
             profiles='/sys/kernel/security/apparmor/profiles', policy='/app/apparmor.txt'):
    current, current_error = _read(proc_current)
    pid1, pid1_error = _read(proc_init)
    profile_list, profiles_error = _read(profiles)
    local_policy, policy_error = _read(policy)
    current_mode=_mode(current)
    current_label=_label(current)
    init_mode=_mode(pid1)
    init_label=_label(pid1)
    active_profile_mode='unavailable'
    if profile_list is not None:
        found=re.search(r'(?m)^'+re.escape(PROFILE)+r'\s+\((enforce|complain|kill|unconfined)\)\s*$',profile_list)
        active_profile_mode=found.group(1).lower() if found else 'not_listed'
    # Only current process (not PID 1) determines whether this MCP tool is confined.
    proven = current_mode=='enforce' and current_label==PROFILE
    return {
        'read_only':True,
        'mcp_process': {'label_matches_expected':current_label==PROFILE if current is not None else None,
                        'mode':current_mode,'enforce_confirmed':proven,
                        'read_error':current_error},
        'container_init_process': {'label_matches_expected':init_label==PROFILE if pid1 is not None else None,
                                   'mode':init_mode,'read_error':pid1_error},
        'securityfs_profile_list': {'mode_for_expected_profile':active_profile_mode,
                                    'read_error':profiles_error},
        'bundled_policy': {**_policy_checks(local_policy),'read_error':policy_error},
        'overall': 'enforce_confirmed' if proven else 'not_confirmed',
        'limitations': ['No prohibited access attempts are performed.',
                         'Bundled AppArmor text may differ from the loaded kernel policy.',
                         'Unavailable kernel paths do not imply the profile is disabled.'],
    }
