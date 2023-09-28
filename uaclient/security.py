import textwrap
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from uaclient import apt, exceptions, livepatch, messages, system, util
from uaclient.api.u.pro.attach.magic.initiate.v1 import _initiate
from uaclient.api.u.pro.attach.magic.revoke.v1 import (
    MagicAttachRevokeOptions,
    _revoke,
)
from uaclient.api.u.pro.attach.magic.wait.v1 import (
    MagicAttachWaitOptions,
    _wait,
)
from uaclient.api.u.pro.security.fix import (
    CVE,
    USN,
    CVEPackageStatus,
    FixStatus,
    UASecurityClient,
    get_affected_packages_from_usn,
    get_cve_affected_source_packages_status,
    get_related_usns,
    group_by_usn_package_status,
    merge_usn_released_binary_package_versions,
    query_installed_source_pkg_versions,
)
from uaclient.clouds.identity import (
    CLOUD_TYPE_TO_TITLE,
    PRO_CLOUD_URLS,
    get_cloud_type,
)
from uaclient.config import UAConfig
from uaclient.defaults import PRINT_WRAP_WIDTH
from uaclient.entitlements import entitlement_factory
from uaclient.entitlements.entitlement_status import (
    ApplicabilityStatus,
    UserFacingStatus,
)
from uaclient.files import notices
from uaclient.files.notices import Notice
from uaclient.status import colorize_commands

CVE_OR_USN_REGEX = (
    r"((CVE|cve)-\d{4}-\d{4,7}$|(USN|usn|LSN|lsn)-\d{1,5}-\d{1,2}$)"
)

API_V1_CVES = "cves.json"
API_V1_CVE_TMPL = "cves/{cve}.json"
API_V1_NOTICES = "notices.json"
API_V1_NOTICE_TMPL = "notices/{notice}.json"


UnfixedPackage = NamedTuple(
    "UnfixedPackage",
    [
        ("pkg", str),
        ("unfixed_reason", str),
    ],
)


FixResult = NamedTuple(
    "FixResult",
    [
        ("status", FixStatus),
        ("unfixed_pkgs", Optional[List[UnfixedPackage]]),
    ],
)


ReleasedPackagesInstallResult = NamedTuple(
    "ReleasedPackagesInstallResult",
    [
        ("fix_status", bool),
        ("unfixed_pkgs", List[UnfixedPackage]),
        ("installed_pkgs", Set[str]),
        ("all_already_installed", bool),
    ],
)


BinaryPackageFix = NamedTuple(
    "BinaryPackageFix",
    [
        ("source_pkg", str),
        ("binary_pkg", str),
        ("fixed_version", str),
    ],
)


UpgradeResult = NamedTuple(
    "UpgradeResult",
    [
        ("status", bool),
        ("failure_reason", Optional[str]),
    ],
)


def _check_cve_fixed_by_livepatch(
    issue_id: str,
) -> Tuple[Optional[FixStatus], Optional[str]]:
    # Check livepatch status for CVE in fixes before checking CVE api
    lp_status = livepatch.status()
    if (
        lp_status is not None
        and lp_status.livepatch is not None
        and lp_status.livepatch.fixes is not None
    ):
        for fix in lp_status.livepatch.fixes:
            if fix.name == issue_id.lower() and fix.patched:
                version = lp_status.livepatch.version or "N/A"
                return (FixStatus.SYSTEM_NON_VULNERABLE, version)

    return (None, None)


def _fix_cve(
    cve: CVE,
    usns: List[USN],
    issue_id: str,
    installed_packages: Dict[str, Dict[str, str]],
    cfg: UAConfig,
    beta_pockets: Dict[str, bool],
    dry_run: bool,
) -> FixStatus:
    affected_pkg_status = get_cve_affected_source_packages_status(
        cve=cve, installed_packages=installed_packages
    )
    usn_released_pkgs = merge_usn_released_binary_package_versions(
        usns, beta_pockets
    )

    print()
    return prompt_for_affected_packages(
        cfg=cfg,
        issue_id=issue_id,
        affected_pkg_status=affected_pkg_status,
        installed_packages=installed_packages,
        usn_released_pkgs=usn_released_pkgs,
        dry_run=dry_run,
    ).status


def _fix_usn(
    usn: USN,
    related_usns: List[USN],
    issue_id: str,
    installed_packages: Dict[str, Dict[str, str]],
    cfg: UAConfig,
    beta_pockets: Dict[str, bool],
    dry_run: bool,
    no_related: bool,
) -> FixStatus:
    # We should only highlight the target USN if we have related USNs to fix
    print(
        "\n" + messages.SECURITY_FIXING_REQUESTED_USN.format(issue_id=issue_id)
    )

    affected_pkg_status = get_affected_packages_from_usn(
        usn=usn, installed_packages=installed_packages
    )
    usn_released_pkgs = merge_usn_released_binary_package_versions(
        [usn], beta_pockets
    )
    target_fix_status, _ = prompt_for_affected_packages(
        cfg=cfg,
        issue_id=issue_id,
        affected_pkg_status=affected_pkg_status,
        installed_packages=installed_packages,
        usn_released_pkgs=usn_released_pkgs,
        dry_run=dry_run,
    )

    if target_fix_status not in (
        FixStatus.SYSTEM_NON_VULNERABLE,
        FixStatus.SYSTEM_NOT_AFFECTED,
    ):
        return target_fix_status

    if not related_usns or no_related:
        return target_fix_status

    print(
        "\n"
        + messages.SECURITY_RELATED_USNS.format(
            related_usns="\n- ".join(usn.id for usn in related_usns)
        )
    )

    print("\n" + messages.SECURITY_FIXING_RELATED_USNS)
    related_usn_status = {}  # type: Dict[str, FixResult]
    for related_usn in related_usns:
        print("- {}".format(related_usn.id))
        affected_pkg_status = get_affected_packages_from_usn(
            usn=related_usn, installed_packages=installed_packages
        )
        usn_released_pkgs = merge_usn_released_binary_package_versions(
            [related_usn], beta_pockets
        )

        related_fix_status = prompt_for_affected_packages(
            cfg=cfg,
            issue_id=related_usn.id,
            affected_pkg_status=affected_pkg_status,
            installed_packages=installed_packages,
            usn_released_pkgs=usn_released_pkgs,
            dry_run=dry_run,
        )

        related_usn_status[related_usn.id] = related_fix_status
        print()

    print(messages.SECURITY_USN_SUMMARY)
    _handle_fix_status_message(
        target_fix_status, issue_id, extra_info=" [requested]"
    )

    failure_on_related_usn = False
    for related_usn in related_usns:
        status = related_usn_status[related_usn.id].status
        _handle_fix_status_message(
            status, related_usn.id, extra_info=" [related]"
        )

        if status == FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT:
            print(
                "- "
                + messages.ENABLE_REBOOT_REQUIRED_TMPL.format(
                    operation="fix operation"
                )
            )
            failure_on_related_usn = True
        if status == FixStatus.SYSTEM_STILL_VULNERABLE:
            unfixed_pkgs = (
                related_usn_status[related_usn.id].unfixed_pkgs or []
            )
            for unfixed_pkg in unfixed_pkgs:
                if unfixed_pkg.unfixed_reason:
                    print(
                        "  - {}: {}".format(
                            unfixed_pkg.pkg, unfixed_pkg.unfixed_reason
                        )
                    )
            failure_on_related_usn = True

    if failure_on_related_usn:
        print(
            "\n"
            + messages.SECURITY_RELATED_USN_ERROR.format(issue_id=issue_id)
        )

    return target_fix_status


def fix_security_issue_id(
    cfg: UAConfig,
    issue_id: str,
    dry_run: bool = False,
    no_related: bool = False,
) -> FixStatus:
    if dry_run:
        print(messages.SECURITY_DRY_RUN_WARNING)

    issue_id = issue_id.upper()
    client = UASecurityClient(cfg=cfg)
    installed_packages = query_installed_source_pkg_versions()

    # Used to filter out beta pockets during merge_usns
    beta_pockets = {
        "esm-apps": _is_pocket_used_by_beta_service(
            messages.SECURITY_UA_APPS_POCKET, cfg
        ),
        "esm-infra": _is_pocket_used_by_beta_service(
            messages.SECURITY_UA_INFRA_POCKET, cfg
        ),
    }

    if "CVE" in issue_id:
        livepatch_cve_status, patch_version = _check_cve_fixed_by_livepatch(
            issue_id
        )

        if livepatch_cve_status:
            print(
                messages.CVE_FIXED_BY_LIVEPATCH.format(
                    issue=issue_id,
                    version=patch_version,
                )
            )
            return livepatch_cve_status

        try:
            cve = client.get_cve(cve_id=issue_id)
            usns = client.get_notices(details=issue_id)
        except exceptions.SecurityAPIError as e:
            if e.code == 404:
                raise exceptions.SecurityIssueNotFound(issue_id=issue_id)
            raise e

        return _fix_cve(
            cve=cve,
            usns=usns,
            issue_id=issue_id,
            installed_packages=installed_packages,
            cfg=cfg,
            beta_pockets=beta_pockets,
            dry_run=dry_run,
        )

    else:  # USN
        try:
            usn = client.get_notice(notice_id=issue_id)
            usns = get_related_usns(usn, client)
        except exceptions.SecurityAPIError as e:
            if e.code == 404:
                raise exceptions.SecurityIssueNotFound(issue_id=issue_id)
            raise e

        if not usn.response["release_packages"]:
            # Since usn.release_packages filters to our current release only
            # check overall metadata and error if empty.
            raise exceptions.SecurityAPIMetadataError(
                error_msg=(
                    "{} metadata defines no fixed package versions."
                ).format(issue_id),
                issue=issue_id,
                extra_info="",
            )

        return _fix_usn(
            usn=usn,
            related_usns=usns,
            issue_id=issue_id,
            installed_packages=installed_packages,
            cfg=cfg,
            beta_pockets=beta_pockets,
            dry_run=dry_run,
            no_related=no_related,
        )


def print_affected_packages_header(
    issue_id: str, affected_pkg_status: Dict[str, CVEPackageStatus]
):
    """Print header strings describing affected packages related to a CVE/USN.

    :param issue_id: String of USN or CVE issue id.
    :param affected_pkg_status: Dict keyed on source package name, with active
        CVEPackageStatus for the current Ubuntu release.
    """
    count = len(affected_pkg_status)
    if count == 0:
        print(
            messages.SECURITY_AFFECTED_PKGS.format(
                count="No", plural_str="s are"
            )
            + "."
        )
        print(
            "\n"
            + messages.SECURITY_ISSUE_UNAFFECTED.format(
                issue=issue_id, extra_info=""
            )
        )
        return

    if count == 1:
        plural_str = " is"
    else:
        plural_str = "s are"
    msg = (
        messages.SECURITY_AFFECTED_PKGS.format(
            count=count, plural_str=plural_str
        )
        + ": "
        + ", ".join(sorted(affected_pkg_status.keys()))
    )
    print(
        textwrap.fill(
            msg,
            width=PRINT_WRAP_WIDTH,
            subsequent_indent="    ",
            replace_whitespace=False,
        )
    )


def _format_packages_message(
    pkg_status_list: List[Tuple[str, CVEPackageStatus]],
    pkg_index: int,
    num_pkgs: int,
) -> str:
    """Format the packages and status to an user friendly message."""
    if not pkg_status_list:
        return ""

    msg_index = []
    src_pkgs = []
    for src_pkg, pkg_status in pkg_status_list:
        pkg_index += 1
        msg_index.append("{}/{}".format(pkg_index, num_pkgs))
        src_pkgs.append(src_pkg)

    msg_header = textwrap.fill(
        "{} {}:".format(
            "(" + ", ".join(msg_index) + ")", ", ".join(sorted(src_pkgs))
        ),
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )
    return "{}\n{}".format(msg_header, pkg_status.status_message)


def _get_service_for_pocket(pocket: str, cfg: UAConfig):
    service_to_check = "no-service-needed"
    if pocket == messages.SECURITY_UA_INFRA_POCKET:
        service_to_check = "esm-infra"
    elif pocket == messages.SECURITY_UA_APPS_POCKET:
        service_to_check = "esm-apps"

    ent_cls = entitlement_factory(cfg=cfg, name=service_to_check)
    return ent_cls(cfg) if ent_cls else None


def _is_pocket_used_by_beta_service(pocket: str, cfg: UAConfig) -> bool:
    """Check if the pocket where the fix is at belongs to a beta service."""
    ent = _get_service_for_pocket(pocket, cfg)
    if ent:
        ent_status, _ = ent.user_facing_status()

        # If the service is already enabled, we proceed with the fix
        # even if the service is a beta stage.
        if ent_status == UserFacingStatus.ACTIVE:
            return False

        return not ent.valid_service

    return False


def _handle_fix_status_message(
    status: FixStatus, issue_id: str, extra_info: str = ""
):
    if status == FixStatus.SYSTEM_NON_VULNERABLE:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    elif status == FixStatus.SYSTEM_NOT_AFFECTED:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_UNAFFECTED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    elif status == FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_NOT_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )
    else:
        print(
            util.handle_unicode_characters(
                messages.SECURITY_ISSUE_NOT_RESOLVED.format(
                    issue=issue_id, extra_info=extra_info
                )
            )
        )


def _handle_released_package_fixes(
    cfg: UAConfig,
    src_pocket_pkgs: Dict[str, List[Tuple[str, CVEPackageStatus]]],
    binary_pocket_pkgs: Dict[str, List[BinaryPackageFix]],
    pkg_index: int,
    num_pkgs: int,
    dry_run: bool,
) -> ReleasedPackagesInstallResult:
    """Handle the packages that could be fixed and have a released status.

    :returns: Tuple of
        boolean whether all packages were successfully upgraded,
        list of strings containing the packages that were not upgraded,
        boolean whether all packages were already installed
    """
    all_already_installed = True
    upgrade_status = True
    unfixed_pkgs = []  # type: List[UnfixedPackage]
    installed_pkgs = set()  # type: Set[str]
    if src_pocket_pkgs:
        for pocket in [
            messages.SECURITY_UBUNTU_STANDARD_UPDATES_POCKET,
            messages.SECURITY_UA_INFRA_POCKET,
            messages.SECURITY_UA_APPS_POCKET,
        ]:
            pkg_src_group = src_pocket_pkgs[pocket]
            binary_pkgs = binary_pocket_pkgs[pocket]
            failure_msg = messages.SECURITY_UA_SERVICE_REQUIRED.format(
                service=pocket
            )

            if upgrade_status:
                msg = _format_packages_message(
                    pkg_status_list=pkg_src_group,
                    pkg_index=pkg_index,
                    num_pkgs=num_pkgs,
                )

                if msg:
                    print(msg)

                    if not binary_pkgs:
                        print(messages.SECURITY_UPDATE_INSTALLED)
                        continue
                    else:
                        # if even one pocket has binary_pkgs to install
                        # then we can't say that everything was already
                        # installed.
                        all_already_installed = False

                upgrade_pkgs = []
                for binary_pkg in sorted(binary_pkgs):
                    check_esm_cache = (
                        pocket
                        != messages.SECURITY_UBUNTU_STANDARD_UPDATES_POCKET
                    )
                    candidate_version = apt.get_pkg_candidate_version(
                        binary_pkg.binary_pkg, check_esm_cache=check_esm_cache
                    )
                    if candidate_version and apt.compare_versions(
                        binary_pkg.fixed_version, candidate_version, "le"
                    ):
                        upgrade_pkgs.append(binary_pkg.binary_pkg)
                    else:
                        unfixed_reason = (
                            messages.FIX_CANNOT_INSTALL_PACKAGE.format(
                                package=binary_pkg.binary_pkg,
                                version=binary_pkg.fixed_version,
                            )
                        )
                        print("- " + unfixed_reason)
                        unfixed_pkgs.append(
                            UnfixedPackage(
                                pkg=binary_pkg.source_pkg,
                                unfixed_reason=unfixed_reason,
                            )
                        )

                pkg_index += len(pkg_src_group)
                upgrade_result = upgrade_packages_and_attach(
                    cfg=cfg,
                    upgrade_pkgs=upgrade_pkgs,
                    pocket=pocket,
                    dry_run=dry_run,
                )
                upgrade_status &= upgrade_result.status
                failure_msg = upgrade_result.failure_reason or ""

            if not upgrade_status:
                unfixed_pkgs.extend(
                    [
                        UnfixedPackage(
                            pkg=src_pkg,
                            unfixed_reason=failure_msg,
                        )
                        for src_pkg, _ in pkg_src_group
                    ]
                )
            else:
                installed_pkgs.update(
                    binary_pkg.binary_pkg for binary_pkg in binary_pkgs
                )

    return ReleasedPackagesInstallResult(
        fix_status=upgrade_status,
        unfixed_pkgs=unfixed_pkgs,
        installed_pkgs=installed_pkgs,
        all_already_installed=all_already_installed,
    )


def _format_unfixed_packages_msg(unfixed_pkgs: List[UnfixedPackage]) -> str:
    """Format the list of unfixed packages into an message.

    :returns: A string containing the message output for the unfixed
              packages.
    """
    sorted_pkgs = sorted({pkg.pkg for pkg in unfixed_pkgs})
    num_pkgs_unfixed = len(sorted_pkgs)
    return textwrap.fill(
        messages.SECURITY_PKG_STILL_AFFECTED.format(
            num_pkgs=num_pkgs_unfixed,
            s="s" if num_pkgs_unfixed > 1 else "",
            verb="are" if num_pkgs_unfixed > 1 else "is",
            pkgs=", ".join(sorted_pkgs),
        ),
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )


def prompt_for_affected_packages(
    cfg: UAConfig,
    issue_id: str,
    affected_pkg_status: Dict[str, CVEPackageStatus],
    installed_packages: Dict[str, Dict[str, str]],
    usn_released_pkgs: Dict[str, Dict[str, Dict[str, str]]],
    dry_run: bool,
) -> FixResult:
    """Process security CVE dict returning a CVEStatus object.

    Since CVEs point to a USN if active, get_notice may be called to fill in
    CVE title details.

    :returns: An FixStatus enum value corresponding to the system state
              after processing the affected packages
    """
    count = len(affected_pkg_status)
    print_affected_packages_header(issue_id, affected_pkg_status)
    if count == 0:
        return FixResult(
            status=FixStatus.SYSTEM_NOT_AFFECTED, unfixed_pkgs=None
        )
    src_pocket_pkgs = defaultdict(list)
    binary_pocket_pkgs = defaultdict(list)
    pkg_index = 0

    pkg_status_groups = group_by_usn_package_status(
        affected_pkg_status, usn_released_pkgs
    )

    unfixed_pkgs = []  # type: List[UnfixedPackage]
    for status_value, pkg_status_group in sorted(pkg_status_groups.items()):
        if status_value != "released":
            fix_result = FixStatus.SYSTEM_NON_VULNERABLE
            print(
                _format_packages_message(
                    pkg_status_list=pkg_status_group,
                    pkg_index=pkg_index,
                    num_pkgs=count,
                )
            )
            pkg_index += len(pkg_status_group)
            status_msg = pkg_status_group[0][1].status_message
            unfixed_pkgs += [
                UnfixedPackage(pkg=src_pkg, unfixed_reason=status_msg)
                for src_pkg, _ in pkg_status_group
            ]
        else:
            for src_pkg, pkg_status in pkg_status_group:
                src_pocket_pkgs[pkg_status.pocket_source].append(
                    (src_pkg, pkg_status)
                )
                for binary_pkg, version in installed_packages[src_pkg].items():
                    usn_released_src = usn_released_pkgs.get(src_pkg, {})
                    if binary_pkg not in usn_released_src:
                        continue
                    fixed_version = usn_released_src.get(binary_pkg, {}).get(
                        "version", ""
                    )

                    if not apt.compare_versions(fixed_version, version, "le"):
                        binary_pocket_pkgs[pkg_status.pocket_source].append(
                            BinaryPackageFix(
                                source_pkg=src_pkg,
                                binary_pkg=binary_pkg,
                                fixed_version=fixed_version,
                            )
                        )

    released_pkgs_install_result = _handle_released_package_fixes(
        cfg=cfg,
        src_pocket_pkgs=src_pocket_pkgs,
        binary_pocket_pkgs=binary_pocket_pkgs,
        pkg_index=pkg_index,
        num_pkgs=count,
        dry_run=dry_run,
    )

    unfixed_pkgs += released_pkgs_install_result.unfixed_pkgs

    print()
    if unfixed_pkgs:
        print(_format_unfixed_packages_msg(unfixed_pkgs))

    if released_pkgs_install_result.fix_status:
        # fix_status is True if either:
        #  (1) we successfully installed all the packages we needed to
        #  (2) we didn't need to install any packages
        # In case (2), then all_already_installed is also True
        if released_pkgs_install_result.all_already_installed:
            # we didn't install any packages, so we're good
            fix_result = (
                FixStatus.SYSTEM_STILL_VULNERABLE
                if unfixed_pkgs
                else FixStatus.SYSTEM_NON_VULNERABLE
            )
        elif system.should_reboot(
            installed_pkgs=released_pkgs_install_result.installed_pkgs
        ):
            # we successfully installed some packages, but
            # system reboot-required. This might be because
            # or our installations.
            reboot_msg = messages.ENABLE_REBOOT_REQUIRED_TMPL.format(
                operation="fix operation"
            )
            print(reboot_msg)
            notices.add(
                Notice.ENABLE_REBOOT_REQUIRED,
                operation="fix operation",
            )
            fix_result = (
                FixStatus.SYSTEM_STILL_VULNERABLE
                if unfixed_pkgs
                else FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT
            )
        else:
            # we successfully installed some packages, and the system
            # reboot-required flag is not set, so we're good
            fix_result = (
                FixStatus.SYSTEM_STILL_VULNERABLE
                if unfixed_pkgs
                else FixStatus.SYSTEM_NON_VULNERABLE
            )
    else:
        fix_result = FixStatus.SYSTEM_STILL_VULNERABLE

    _handle_fix_status_message(fix_result, issue_id)
    return FixResult(
        status=fix_result,
        unfixed_pkgs=unfixed_pkgs,
    )


def _inform_ubuntu_pro_existence_if_applicable() -> None:
    """Alert the user when running Pro on cloud with PRO support."""
    cloud_type, _ = get_cloud_type()
    if cloud_type in PRO_CLOUD_URLS:
        print(
            messages.SECURITY_USE_PRO_TMPL.format(
                title=CLOUD_TYPE_TO_TITLE.get(cloud_type),
                cloud_specific_url=PRO_CLOUD_URLS.get(cloud_type),
            )
        )


def _run_ua_attach(cfg: UAConfig, token: str) -> bool:
    """Attach to an Ubuntu Pro subscription with a given token.

    :return: True if attach performed without errors.
    """
    import argparse

    from uaclient import cli

    print(colorize_commands([["pro", "attach", token]]))
    try:
        ret_code = cli.action_attach(
            argparse.Namespace(
                token=token, auto_enable=True, format="cli", attach_config=None
            ),
            cfg,
        )
        return ret_code == 0
    except exceptions.UbuntuProError as err:
        print(err.msg)
        return False


def _perform_magic_attach(cfg: UAConfig):
    print(messages.CLI_MAGIC_ATTACH_INIT)
    initiate_resp = _initiate(cfg=cfg)
    print(
        "\n"
        + messages.CLI_MAGIC_ATTACH_SIGN_IN.format(
            user_code=initiate_resp.user_code
        )
    )

    wait_options = MagicAttachWaitOptions(magic_token=initiate_resp.token)

    try:
        wait_resp = _wait(options=wait_options, cfg=cfg)
    except exceptions.MagicAttachTokenError as e:
        print(messages.CLI_MAGIC_ATTACH_FAILED)

        revoke_options = MagicAttachRevokeOptions(
            magic_token=initiate_resp.token
        )
        _revoke(options=revoke_options, cfg=cfg)
        raise e

    print("\n" + messages.CLI_MAGIC_ATTACH_PROCESSING)
    return _run_ua_attach(cfg, wait_resp.contract_token)


def _prompt_for_attach(cfg: UAConfig) -> bool:
    """Prompt for attach to a subscription or token.

    :return: True if attach performed.
    """
    _inform_ubuntu_pro_existence_if_applicable()
    print(messages.SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION)
    choice = util.prompt_choices(
        messages.SECURITY_FIX_ATTACH_PROMPT,
        valid_choices=["s", "a", "c"],
    )
    if choice == "c":
        return False
    if choice == "s":
        return _perform_magic_attach(cfg)
    if choice == "a":
        print(messages.PROMPT_ENTER_TOKEN)
        token = input("> ")
        return _run_ua_attach(cfg, token)

    return True


def _prompt_for_enable(cfg: UAConfig, service: str) -> bool:
    """Prompt for enable a pro service.

    :return: True if enable performed.
    """
    import argparse

    from uaclient import cli

    print(messages.SECURITY_SERVICE_DISABLED.format(service=service))
    choice = util.prompt_choices(
        messages.SECURITY_FIX_ENABLE_PROMPT.format(service),
        valid_choices=["e", "c"],
    )

    if choice == "e":
        print(colorize_commands([["pro", "enable", service]]))
        return bool(
            0
            == cli.action_enable(
                argparse.Namespace(
                    service=[service],
                    assume_yes=True,
                    beta=False,
                    format="cli",
                    access_only=False,
                ),
                cfg,
            )
        )

    return False


def _check_attached(cfg: UAConfig, dry_run: bool) -> bool:
    """Verify if machine is attached to an Ubuntu Pro subscription."""
    if dry_run:
        print("\n" + messages.SECURITY_DRY_RUN_UA_NOT_ATTACHED)
        return True
    return _prompt_for_attach(cfg)


def _check_subscription_for_required_service(
    pocket: str, cfg: UAConfig, dry_run: bool
) -> bool:
    """
    Verify if the Ubuntu Pro subscription has the required service enabled.
    """
    ent = _get_service_for_pocket(pocket, cfg)

    if ent:
        ent_status, _ = ent.user_facing_status()

        if ent_status == UserFacingStatus.ACTIVE:
            return True

        applicability_status, _ = ent.applicability_status()
        if applicability_status == ApplicabilityStatus.APPLICABLE:
            if dry_run:
                print(
                    "\n"
                    + messages.SECURITY_DRY_RUN_UA_SERVICE_NOT_ENABLED.format(
                        service=ent.name
                    )
                )
                return True

            if _prompt_for_enable(cfg, ent.name):
                return True
            else:
                print(
                    messages.SECURITY_UA_SERVICE_NOT_ENABLED.format(
                        service=ent.name
                    )
                )
        else:
            print(
                messages.SECURITY_UA_SERVICE_NOT_ENTITLED.format(
                    service=ent.name
                )
            )

    return False


def _prompt_for_new_token(cfg: UAConfig) -> bool:
    """Prompt for attach a new subscription token to the user.

    :return: True if attach performed.
    """
    import argparse

    from uaclient import cli

    _inform_ubuntu_pro_existence_if_applicable()
    print(messages.SECURITY_UPDATE_NOT_INSTALLED_EXPIRED)
    choice = util.prompt_choices(
        messages.SECURITY_FIX_RENEW_PROMPT,
        valid_choices=["r", "c"],
    )
    if choice == "r":
        print(messages.PROMPT_EXPIRED_ENTER_TOKEN)
        token = input("> ")
        print(colorize_commands([["pro", "detach"]]))
        cli.action_detach(
            argparse.Namespace(assume_yes=True, format="cli"), cfg
        )
        return _run_ua_attach(cfg, token)

    return False


def _check_subscription_is_expired(
    status_cache: Dict[str, Any], cfg: UAConfig, dry_run: bool
) -> bool:
    """Check if the Ubuntu Pro subscription is expired.

    :returns: True if subscription is expired and not renewed.
    """
    attached = status_cache.get("attached", False)
    if not attached:
        return False

    contract_expiry_datetime = status_cache.get("expires")
    # If we don't have an expire information on the status-cache, we
    # assume that the contract is expired.
    if contract_expiry_datetime is None or (
        contract_expiry_datetime
        < datetime.now(contract_expiry_datetime.tzinfo)
    ):
        if dry_run:
            print(messages.SECURITY_DRY_RUN_UA_EXPIRED_SUBSCRIPTION)
            return False
        return not _prompt_for_new_token(cfg)

    return False


def upgrade_packages_and_attach(
    cfg: UAConfig, upgrade_pkgs: List[str], pocket: str, dry_run: bool
) -> UpgradeResult:
    """Upgrade available packages to fix a CVE.

    Upgrade all packages in upgrades_packages and, if necessary,
    prompt regarding system attach prior to upgrading Ubuntu Pro packages.

    :return: True if package upgrade completed or unneeded, False otherwise.
    """
    if not upgrade_pkgs:
        return UpgradeResult(status=True, failure_reason=None)

    # If we are running on --dry-run mode, we don't need to be root
    # to understand what will happen with the system
    if not util.we_are_currently_root() and not dry_run:
        msg = messages.SECURITY_APT_NON_ROOT
        print(msg)
        return UpgradeResult(status=False, failure_reason=msg)

    if pocket != messages.SECURITY_UBUNTU_STANDARD_UPDATES_POCKET:
        # We are now using status-cache because non-root users won't
        # have access to the private machine_token.json file. We
        # can use the status-cache as a proxy for the attached
        # information
        status_cache = cfg.read_cache("status-cache") or {}
        if not status_cache.get("attached", False):
            if not _check_attached(cfg, dry_run):
                return UpgradeResult(
                    status=False,
                    failure_reason=messages.SECURITY_UA_SERVICE_REQUIRED.format(  # noqa
                        service=pocket
                    ),
                )
        elif _check_subscription_is_expired(
            status_cache=status_cache, cfg=cfg, dry_run=dry_run
        ):
            return UpgradeResult(
                status=False,
                failure_reason=messages.SECURITY_UA_SERVICE_WITH_EXPIRED_SUB.format(  # noqa
                    service=pocket
                ),
            )

        if not _check_subscription_for_required_service(pocket, cfg, dry_run):
            # User subscription does not have required service enabled
            return UpgradeResult(
                status=False,
                failure_reason=messages.SECURITY_UA_SERVICE_NOT_ENABLED_SHORT.format(  # noqa
                    service=pocket
                ),
            )

    print(
        colorize_commands(
            [
                ["apt", "update", "&&"]
                + ["apt", "install", "--only-upgrade", "-y"]
                + sorted(upgrade_pkgs)
            ]
        )
    )

    if not dry_run:
        try:
            apt.run_apt_update_command()
            apt.run_apt_command(
                cmd=["apt-get", "install", "--only-upgrade", "-y"]
                + upgrade_pkgs,
                override_env_vars={"DEBIAN_FRONTEND": "noninteractive"},
            )
        except Exception as e:
            msg = getattr(e, "msg", str(e))
            print(msg.strip())
            return UpgradeResult(
                status=False, failure_reason=messages.SECURITY_UA_APT_FAILURE
            )

    return UpgradeResult(status=True, failure_reason=None)
