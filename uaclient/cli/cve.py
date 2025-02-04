from collections import namedtuple

from uaclient import messages
from uaclient.api.u.pro.security.fix._common import (
    query_installed_source_pkg_versions,
)
from uaclient.api.u.pro.security.vulnerabilities.cve.v1 import (
    CVEVulnerabilitiesOptions,
    _vulnerabilities,
)
from uaclient.cli import cli_util
from uaclient.cli.commands import ProArgument, ProArgumentGroup, ProCommand
from uaclient.cli.formatter import Table
from uaclient.config import UAConfig

AffectedPackage = namedtuple(
    "AffectedPackage", ["name", "fix_status", "fix_origin", "fix_version"]
)


@cli_util.with_spinner(msg=messages.CLI_CVES_SPINNER_MSG)
def _get_cve_vulnerabilities(args, *, cfg: UAConfig, **kwargs):
    return _vulnerabilities(options=CVEVulnerabilitiesOptions(), cfg=cfg)


def _get_affected_pkgs(cve_vulnerabilities, cve_info, cve_name):
    rows = []
    installed_pkgs_by_source = query_installed_source_pkg_versions()

    for source_pkg in cve_info.related_packages:
        binary_pkgs = installed_pkgs_by_source.get(source_pkg, {}).keys()

        for binary_pkg in sorted(binary_pkgs):
            binary_pkg_info = cve_vulnerabilities.packages.get(binary_pkg)

            if binary_pkg_info:
                binary_pkg_cve_info = None
                for cve in binary_pkg_info.cves:
                    if cve.name == cve_name:
                        binary_pkg_cve_info = cve
                        break

                if binary_pkg_cve_info:
                    rows.append(
                        AffectedPackage(
                            name=binary_pkg,
                            fix_status=binary_pkg_cve_info.fix_status,
                            fix_origin=binary_pkg_cve_info.fix_origin,
                            fix_version=binary_pkg_cve_info.fix_version,
                        )
                    )

        return rows


def _format_affected_pkgs(affected_pkgs):
    formatted_rows = []

    for affected_pkg in affected_pkgs:
        if affected_pkg.fix_status == "fixed":
            formatted_rows.append(
                [
                    "<SPACE>{}:".format(affected_pkg.name),
                    affected_pkg.fix_status,
                    "({})".format(affected_pkg.fix_origin),
                    affected_pkg.fix_version,
                ]
            )
        else:
            formatted_rows.append(
                [
                    "<SPACE>{}:".format(affected_pkg.name),
                    affected_pkg.fix_status,
                    "",
                    "",
                ]
            )

    return formatted_rows


def action_cve(args, *, cfg, **kwargs):
    cve_vulnerabilities = _get_cve_vulnerabilities(args, cfg=cfg)

    if args.cve not in cve_vulnerabilities.cves:
        print(messages.CLI_CVE_NOT_AFFECTED.format(issue=args.cve))
        return

    cve_info = cve_vulnerabilities.cves[args.cve]
    affected_pkgs_rows = _format_affected_pkgs(
        _get_affected_pkgs(cve_vulnerabilities, cve_info, args.cve)
    )
    affected_pkgs_table = Table(rows=affected_pkgs_rows)

    print("name:               {}".format(args.cve))
    print(
        "public-url:         https://ubuntu.com/security/{}".format(args.cve)
    )
    print(
        "published-at:       {}".format(
            cve_info.published_at.strftime("%Y-%m-%d")
        )
    )
    print(
        "cve-cache-date:     {}".format(
            cve_vulnerabilities.vulnerability_data_published_at.strftime(
                "%Y-%m-%d"
            )
        )
    )
    print(
        "apt-cache-date:     {}".format(
            cve_vulnerabilities.apt_updated_at.strftime("%Y-%m-%d")
        )
    )
    print(
        "priority:           {}".format(
            cli_util.colorize_priority(cve_info.priority)
        )
    )
    print("cvss-score:         {}".format(cve_info.cvss_score))
    print("cvss-severity:      {}".format(cve_info.cvss_severity))
    print(
        "description: |\n  {}".format(
            cve_info.description.replace("\n", "\n  ")
        )
    )

    if cve_info.notes:
        print(
            "notes:\n{}".format(
                "\n".join(
                    "  - {}".format(note.replace("\n", "\n    "))
                    for note in cve_info.notes
                )
            )
        )

    print(
        "affected_packages:\n{}".format(
            affected_pkgs_table.to_string().strip().replace("<SPACE>", "  ")
        )
    )

    if cve_info.related_usns:
        related_usns = [
            "  {}: {}".format(usn.name, usn.title)
            for usn in cve_info.related_usns
            if usn.title
        ]

        if related_usns:
            print("related_usns:\n{}".format("\n".join(related_usns)))


cve_command = ProCommand(
    "cve",
    help=messages.CLI_CVE,
    description=messages.CLI_CVE_DESC,
    action=action_cve,
    preserve_description=True,
    argument_groups=[
        ProArgumentGroup(
            arguments=[
                ProArgument(
                    "cve",
                    help=messages.CLI_CVE_ISSUE,
                ),
            ]
        )
    ],
)
