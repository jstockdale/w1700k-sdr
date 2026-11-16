# SPDX-License-Identifier: MIT
"""Update an installed unit from the current build, whatever state it is in.

The console tells where the unit is (stock, loader, dumper, Linux, or off); the
tool brings it to the installed loader's prompt, rewrites the requested parts,
reads each one back, and boots the result. A volume that already holds the new
bytes is not rewritten, so repeating an update is cheap.
"""
from . import config, layout, provision, stock, steps
from . import console as unit
from .console import StepFailed
from .session import open_session


NOT_INSTALLED = 'stock does not boot our loader; install the unit with init/install'


def detect(settings):
    """Report the console state; transmits one Ctrl-C and nothing else."""
    with open_session(settings, 'detect', passive=True) as session:
        state = unit.identify(session.console, session.log)
    print(f'flash: the unit is at: {state}')
    return 0


def run(settings, serial=None, fit=False, rootfs=False, durable=False, loader=False,
        recovery=False, boot=True, authorized_key=None, no_login_key=False):
    wanted = [config.SYSTEM_FIT] if fit else []
    wanted += [config.ROOTFS] if rootfs else []
    wanted += list(config.DURABLES) if durable else []
    wanted += [config.LOADER] if loader else []
    wanted += [config.RECOVERY_FIT] if recovery else []
    config.require_images(*wanted)
    image = login_key = None
    if rootfs:
        serial = config.pick_unit(settings.data_dir, serial)
        if not no_login_key:
            login_key = provision.authorized_key(authorized_key)       # fail before touching the unit
        image = provision.provision(config.unit_dir(settings.data_dir, serial), address=settings.device_ip)
    with open_session(settings, 'flash', write=not recovery) as session:
        console, log = session.console, session.log
        state = unit.identify(console, log)
        print(f'flash: the unit is at: {state}')
        if loader:
            # The layout is read from the loader the unit has, before one for this build's
            # layout takes its place. A loader that does not come up is the one case it cannot
            # be read in, and the one a loader update is there to mend.
            unit.to_stock(console, log, state)
            if layout.bootcmd_extent(stock.environment(console).get('bootcmd')) is None:
                raise StepFailed(NOT_INSTALLED)
            try:
                unit.to_installed_loader(console, log, 'stock')
            except StepFailed:
                print('flash: the installed loader did not come up, so how the unit is laid out '
                      'could not be read from it; writing the loader as asked')
                state = None
            else:
                steps.check_layout(session)
                state = 'loader'
            update_loader(session, state)
            state = 'loader'
        unit.to_installed_loader(console, log, state)
        if not (loader or recovery):        # recovery writes nothing and attaches no flash
            steps.check_layout(session)
        if recovery:
            status = steps.boot_recovery(session)
            print(f'flash: recovery system running from RAM; {status}')
            return 0
        if fit or rootfs:
            steps.attach(session, 'system')
            steps.loader_network(session)
            if fit:
                steps.write_volume(session, 'fit', config.SYSTEM_FIT, fit=True,
                                   skip_current=True)
            if rootfs:
                steps.write_volume(session, 'rootfs', image, skip_current=True)
            steps.detach(session)
        if durable:
            steps.format_durable(session, steps.loader_nand(session))
        if not boot:
            print('flash: left at the loader prompt')
            return 0
        status = steps.boot_installed(session)
        if rootfs:
            host_keys(session, config.unit_dir(settings.data_dir, serial), settings.device_ip)
            login_keys(session, login_key)
    print(f'flash: done; {status}')
    return 0


def host_keys(session, directory, address):
    """After a root was written over the console: the host key the unit now answers with is
    recorded, and said when it is not the one this host knew the unit by (a root from before
    host keys left the root had its key built in, and that key went with it)."""
    known = directory / provision.KNOWN_HOSTS
    before = known.read_text() if known.is_file() else None
    lines = steps.host_keys(session)
    if lines is None:
        print("flash: this unit's loader does not hand its ssh host key to the system, so the unit has\n"
              '       another host key at every boot. Flash the loader too (init/flash --loader)')
        return
    provision.known_host(directory, address, lines)
    if before is not None and known.read_text() != before:
        print(f'flash: the unit has a new ssh host key, recorded in {known}; a host that knew the old '
              'one will say so')


def login_keys(session, login_key):
    """After a root was written over the console: a unit left with no login key in its list is
    given `login_key` (None: none, --no-login-key). A root from before the list left the root
    had its key built in, and that key went with it."""
    count, loader = steps.login_keys(session)
    if loader == 'silent':
        print("flash: this unit's loader does not hand its login keys to the system, so nothing can log in\n"
              '       but its paperclip key. Flash the loader too (init/flash --loader)')
    elif count == 0 and login_key is not None:
        named = steps.add_login_key(session, login_key)
        print(f'flash: the unit had no login key in its list; yours is in it now, as "{named}"')


def update_loader(session, state):
    """Rewrite the `loader` partition through stock, then fix bootcmd if needed."""
    console, log = session.console, session.log
    unit.to_stock(console, log, state)
    installed = layout.bootcmd_extent(stock.environment(console).get('bootcmd'))
    if installed is None:
        raise StepFailed(NOT_INSTALLED)
    extent = steps.write_loader_slot(session)
    if extent != installed:
        unit.to_stock(console, log, 'loader')
        steps.save_bootcmd(session, extent)
        unit.to_installed_loader(console, log, 'stock')
