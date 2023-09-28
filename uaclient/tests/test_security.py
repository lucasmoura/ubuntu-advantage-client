import json
import textwrap

import mock
import pytest

from uaclient import exceptions, livepatch
from uaclient.clouds.identity import NoCloudTypeReason
from uaclient.entitlements.entitlement_status import (
    ApplicabilityStatus,
    UserFacingStatus,
)
from uaclient.files.notices import Notice
from uaclient.messages import (
    ENABLE_REBOOT_REQUIRED_TMPL,
    FAIL_X,
    OKGREEN_CHECK,
    PROMPT_ENTER_TOKEN,
    PROMPT_EXPIRED_ENTER_TOKEN,
    SECURITY_APT_NON_ROOT,
    SECURITY_CVE_STATUS_IGNORED,
    SECURITY_CVE_STATUS_NEEDED,
    SECURITY_CVE_STATUS_PENDING,
    SECURITY_CVE_STATUS_TRIAGE,
    SECURITY_DRY_RUN_UA_NOT_ATTACHED,
    SECURITY_DRY_RUN_UA_SERVICE_NOT_ENABLED,
    SECURITY_FIXING_REQUESTED_USN,
    SECURITY_RELATED_USN_ERROR,
    SECURITY_SERVICE_DISABLED,
    SECURITY_UA_SERVICE_NOT_ENABLED,
    SECURITY_UA_SERVICE_NOT_ENTITLED,
    SECURITY_UA_SERVICE_REQUIRED,
    SECURITY_UPDATE_NOT_INSTALLED_EXPIRED,
    SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
    SECURITY_USE_PRO_TMPL,
)
from uaclient.security import (
    CVEPackageStatus,
    FixStatus,
    UASecurityClient,
    UnfixedPackage,
    UpgradeResult,
    _check_attached,
    _check_subscription_for_required_service,
    _fix_usn,
    _prompt_for_attach,
    fix_security_issue_id,
    merge_usn_released_binary_package_versions,
    prompt_for_affected_packages,
    upgrade_packages_and_attach,
)
from uaclient.status import colorize_commands
from uaclient.testing import fakes

M_PATH = "uaclient.contract."
M_REPO_PATH = "uaclient.entitlements.repo.RepoEntitlement."


SAMBA_CVE_STATUS_BIONIC = {
    "component": None,
    "description": "2:4.7.6+dfsg~ubuntu-0ubuntu2.19",
    "pocket": None,
    "release_codename": "bionic",
    "status": "released",
}
SAMBA_CVE_STATUS_FOCAL = {
    "component": None,
    "description": "2:4.11.6+dfsg-0ubuntu1.4",
    "pocket": None,
    "release_codename": "focal",
    "status": "not-affected",
}
SAMBA_CVE_STATUS_UPSTREAM = {
    "component": None,
    "description": "",
    "pocket": None,
    "release_codename": "upstream",
    "status": "needs-triage",
}

SAMPLE_CVE_RESPONSE = {
    "bugs": ["https://bugzilla.samba.org/show_bug.cgi?id=14497"],
    "description": "\nAn elevation of privilege vulnerability exists ...",
    "id": "CVE-2020-1472",
    "notes": [{"author": "..", "note": "..."}],
    "notices_ids": ["USN-4510-1", "USN-4510-2", "USN-4559-1"],
    "packages": [
        {
            "debian": "https://tracker.debian.org/pkg/samba",
            "name": "samba",
            "source": "https://ubuntu.com/security/cve?package=samba",
            "statuses": [
                SAMBA_CVE_STATUS_BIONIC,
                SAMBA_CVE_STATUS_FOCAL,
                SAMBA_CVE_STATUS_UPSTREAM,
            ],
        }
    ],
    "status": "active",
}

SAMPLE_USN_RESPONSE = {
    "cves_ids": ["CVE-2020-1473", "CVE-2020-1472"],
    "id": "USN-4510-2",
    "instructions": "In general, a standard system update will make all ...\n",
    "references": [],
    "release_packages": {
        "series-example-1": [
            {
                "description": "SMB/CIFS file, print, and login ... Unix",
                "is_source": True,
                "name": "samba",
                "version": "2:4.3.11+dfsg-0ubuntu0.14.04.20+esm9",
            },
            {
                "is_source": False,
                "name": "samba",
                "source_link": "https://launchpad.net/ubuntu/+source/samba",
                "version": "2~14.04.1+esm9",
                "version_link": "https://....11+dfsg-0ubuntu0.14.04.20+esm9",
            },
        ],
        "series-example-2": [
            {
                "description": "high-level 3D graphics kit implementing ...",
                "is_source": True,
                "name": "coin3",
                "version": "3.1.4~abc9f50-4ubuntu2+esm1",
            },
            {
                "is_source": False,
                "name": "libcoin80-runtime",
                "source_link": "https://launchpad.net/ubuntu/+source/coin3",
                "version": "3~18.04.1+esm2",
                "version_link": "https://coin3...18.04.1+esm2",
            },
        ],
    },
    "summary": "Samba would allow unintended access to files over the ....\n",
    "title": "Samba vulnerability",
    "type": "USN",
}

SAMPLE_USN_RESPONSE_NO_CVES = {
    "cves_ids": [],
    "id": "USN-4038-3",
    "instructions": "In general, a standard system update will make all ...\n",
    "references": ["https://launchpad.net/bugs/1834494"],
    "release_packages": {
        "bionic": [
            {
                "description": "high-level 3D graphics kit implementing ...",
                "is_source": True,
                "name": "coin3",
                "version": "3.1.4~abc9f50-4ubuntu2+esm1",
            },
            {
                "is_source": False,
                "name": "libcoin80-runtime",
                "source_link": "https://launchpad.net/ubuntu/+source/coin3",
                "version": "3~18.04.1+esm2",
                "version_link": "https://coin3...18.04.1+esm2",
                "pocket": "security",
            },
        ]
    },
    "summary": "",
    "title": "USN vulnerability",
    "type": "USN",
}


CVE_PKG_STATUS_NEEDED = {
    "description": "2.1",
    "pocket": None,
    "status": "needed",
}
CVE_PKG_STATUS_IGNORED = {
    "description": "2.1",
    "pocket": None,
    "status": "ignored",
}
CVE_PKG_STATUS_DEFERRED = {
    "description": "2.1",
    "pocket": None,
    "status": "deferred",
}
CVE_PKG_STATUS_NEEDS_TRIAGE = {
    "description": "2.1",
    "pocket": None,
    "status": "needs-triage",
}
CVE_PKG_STATUS_PENDING = {
    "description": "2.1",
    "pocket": None,
    "status": "pending",
}
CVE_PKG_STATUS_RELEASED = {
    "description": "2.1",
    "pocket": "updates",
    "status": "released",
}
CVE_PKG_STATUS_RELEASED_ESM_INFRA = {
    "description": "2.1",
    "pocket": "esm-infra",
    "status": "released",
}
CVE_PKG_STATUS_RELEASED_ESM_APPS = {
    "description": "2.1",
    "pocket": "esm-apps",
    "status": "released",
}
CVE_PKG_STATUS_NEEDED = {"description": "", "pocket": None, "status": "needed"}


class TestPromptForAffectedPackages:
    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,"
        "usn_released_pkgs,cloud_type,expected,expected_ret,"
        "expected_unfixed_pkgs",
        (
            (  # No affected_packages listed
                {},
                {"curl": {"curl": "1.0"}},
                {"unread-because-no-affected-pkgs": {}},
                (None, NoCloudTypeReason.NO_CLOUD_DETECTED),
                textwrap.dedent(
                    """\
                   No affected source packages are installed.

                   {check} USN-### does not affect your system.
                   """.format(
                        check=OKGREEN_CHECK  # noqa: E126
                    )  # noqa: E126
                ),
                FixStatus.SYSTEM_NOT_AFFECTED,
                None,
            ),
            (  # version is >= released affected package
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED)},
                {"slsrc": {"sl": "2.1"}},
                {"slsrc": {"sl": {"version": "2.1"}}},
                (None, NoCloudTypeReason.NO_CLOUD_DETECTED),
                textwrap.dedent(
                    """\
                   1 affected source package is installed: slsrc
                   (1/1) slsrc:
                   A fix is available in Ubuntu standard updates.
                   The update is already installed.

                   {check} USN-### is resolved.
                   """.format(
                        check=OKGREEN_CHECK  # noqa: E126
                    )  # noqa: E126
                ),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
            (  # usn_released_pkgs version is used instead of CVE (2.1)
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED)},
                {"slsrc": {"sl": "2.1"}},
                {"slsrc": {"sl": {"version": "2.2"}}},
                (None, NoCloudTypeReason.NO_CLOUD_DETECTED),
                textwrap.dedent(
                    """\
                   1 affected source package is installed: slsrc
                   (1/1) slsrc:
                   A fix is available in Ubuntu standard updates.
                   """
                )
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y sl"]]
                )
                + "\n\n"
                + "{check} USN-### is resolved.\n".format(check=OKGREEN_CHECK),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
            (  # version is < released affected package standard updates
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED)},
                {"slsrc": {"sl": "2.0"}},
                {"slsrc": {"sl": {"version": "2.1"}}},
                (None, NoCloudTypeReason.NO_CLOUD_DETECTED),
                textwrap.dedent(
                    """\
                   1 affected source package is installed: slsrc
                   (1/1) slsrc:
                   A fix is available in Ubuntu standard updates.
                   """
                )
                + "\n".join(
                    [
                        colorize_commands(
                            [
                                [
                                    "apt update && apt install --only-upgrade"
                                    " -y sl"
                                ]
                            ]
                        ),
                        "",
                        "{check} USN-### is resolved.\n".format(
                            check=OKGREEN_CHECK
                        ),
                    ]
                ),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
            (  # version is < released affected package esm-infra updates
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"slsrc": {"sl": "2.0"}},
                {"slsrc": {"sl": {"version": "2.1"}}},
                ("azure", None),
                textwrap.dedent(
                    """\
                    1 affected source package is installed: slsrc
                    (1/1) slsrc:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + "\n".join(
                    [
                        SECURITY_USE_PRO_TMPL.format(
                            title="Azure",
                            cloud_specific_url="https://ubuntu.com/azure/pro",
                        ),
                        SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
                    ]
                ),
                FixStatus.SYSTEM_STILL_VULNERABLE,
                [
                    UnfixedPackage(
                        pkg="slsrc",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Infra"
                        ),
                    ),
                ],
            ),
            (  # version < released package in esm-infra updates and aws cloud
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"slsrc": {"sl": "2.0"}},
                {"slsrc": {"sl": {"version": "2.1"}}},
                ("aws", None),
                textwrap.dedent(
                    """\
                    1 affected source package is installed: slsrc
                    (1/1) slsrc:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + "\n".join(
                    [
                        SECURITY_USE_PRO_TMPL.format(
                            title="AWS",
                            cloud_specific_url="https://ubuntu.com/aws/pro",
                        ),
                        SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
                    ]
                ),
                FixStatus.SYSTEM_STILL_VULNERABLE,
                [
                    UnfixedPackage(
                        pkg="slsrc",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Infra"
                        ),
                    ),
                ],
            ),
            (  # version is < released affected both esm-apps and standard
                {
                    "slsrc": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_APPS
                    ),
                    "curl": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                },
                {"slsrc": {"sl": "2.0"}, "curl": {"curl": "2.0"}},
                {
                    "slsrc": {"sl": {"version": "2.1"}},
                    "curl": {"curl": {"version": "2.1"}},
                },
                ("gce", None),
                textwrap.dedent(
                    """\
                    2 affected source packages are installed: curl, slsrc
                    (1/2) curl:
                    A fix is available in Ubuntu standard updates.
                    """
                )
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y curl"]]
                )
                + "\n"
                + textwrap.dedent(
                    """\
                    (2/2) slsrc:
                    A fix is available in Ubuntu Pro: ESM Apps.
                    """
                )
                + "\n".join(
                    [
                        SECURITY_USE_PRO_TMPL.format(
                            title="GCP",
                            cloud_specific_url="https://ubuntu.com/gcp/pro",
                        ),
                        SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
                    ]
                )
                + "\n\n"
                + "1 package is still affected: slsrc",
                FixStatus.SYSTEM_STILL_VULNERABLE,
                [
                    UnfixedPackage(
                        pkg="slsrc",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Apps"
                        ),
                    ),
                ],
            ),
            (  # version is < released affected both esm-apps and standard
                {
                    "pkg1": CVEPackageStatus(CVE_PKG_STATUS_IGNORED),
                    "pkg2": CVEPackageStatus(CVE_PKG_STATUS_IGNORED),
                    "pkg3": CVEPackageStatus(CVE_PKG_STATUS_PENDING),
                    "pkg4": CVEPackageStatus(CVE_PKG_STATUS_PENDING),
                    "pkg5": CVEPackageStatus(CVE_PKG_STATUS_NEEDS_TRIAGE),
                    "pkg6": CVEPackageStatus(CVE_PKG_STATUS_NEEDS_TRIAGE),
                    "pkg7": CVEPackageStatus(CVE_PKG_STATUS_NEEDED),
                    "pkg8": CVEPackageStatus(CVE_PKG_STATUS_NEEDED),
                    "pkg9": CVEPackageStatus(CVE_PKG_STATUS_DEFERRED),
                    "pkg10": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                    "pkg11": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                    "pkg12": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_INFRA
                    ),
                    "pkg13": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_INFRA
                    ),
                    "pkg14": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_APPS
                    ),
                    "pkg15": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_APPS
                    ),
                },
                {
                    "pkg10": {"pkg10": "2.0"},
                    "pkg11": {"pkg11": "2.0"},
                    "pkg12": {"pkg12": "2.0"},
                    "pkg13": {"pkg13": "2.0"},
                    "pkg14": {"pkg14": "2.0"},
                    "pkg15": {"pkg15": "2.0"},
                },
                {
                    "pkg10": {"pkg10": {"version": "2.1"}},
                    "pkg11": {"pkg11": {"version": "2.1"}},
                    "pkg12": {"pkg12": {"version": "2.1"}},
                    "pkg13": {"pkg13": {"version": "2.1"}},
                    "pkg14": {"pkg14": {"version": "2.1"}},
                    "pkg15": {"pkg15": {"version": "2.1"}},
                },
                ("gce", None),
                textwrap.dedent(
                    """\
                    15 affected source packages are installed: {}
                    (1/15, 2/15, 3/15) pkg1, pkg2, pkg9:
                    Sorry, no fix is available.
                    (4/15, 5/15) pkg7, pkg8:
                    Sorry, no fix is available yet.
                    (6/15, 7/15) pkg5, pkg6:
                    Ubuntu security engineers are investigating this issue.
                    (8/15, 9/15) pkg3, pkg4:
                    A fix is coming soon. Try again tomorrow.
                    (10/15, 11/15) pkg10, pkg11:
                    A fix is available in Ubuntu standard updates.
                    """
                ).format(
                    (
                        "pkg1, pkg10, pkg11, pkg12, pkg13,\n"
                        "    pkg14, pkg15, pkg2, pkg3, pkg4, pkg5, pkg6, pkg7,"
                        " pkg8, pkg9"
                    )
                )
                + colorize_commands(
                    [
                        [
                            "apt update && apt install --only-upgrade"
                            " -y pkg10 pkg11"
                        ]
                    ]
                )
                + "\n"
                + textwrap.dedent(
                    """\
                    (12/15, 13/15) pkg12, pkg13:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + "\n".join(
                    [
                        SECURITY_USE_PRO_TMPL.format(
                            title="GCP",
                            cloud_specific_url="https://ubuntu.com/gcp/pro",
                        ),
                        SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
                    ]
                )
                + "\n\n"
                + "13 packages are still affected: {}".format(
                    (
                        "pkg1, pkg12, pkg13, pkg14, pkg15, pkg2, pkg3,\n"
                        "    pkg4, pkg5, pkg6, pkg7, pkg8, pkg9"
                    )
                ),
                FixStatus.SYSTEM_STILL_VULNERABLE,
                [
                    UnfixedPackage(
                        pkg="pkg1",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg2",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg9",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg7",
                        unfixed_reason=SECURITY_CVE_STATUS_NEEDED,
                    ),
                    UnfixedPackage(
                        pkg="pkg8",
                        unfixed_reason=SECURITY_CVE_STATUS_NEEDED,
                    ),
                    UnfixedPackage(
                        pkg="pkg5",
                        unfixed_reason=SECURITY_CVE_STATUS_TRIAGE,
                    ),
                    UnfixedPackage(
                        pkg="pkg6",
                        unfixed_reason=SECURITY_CVE_STATUS_TRIAGE,
                    ),
                    UnfixedPackage(
                        pkg="pkg3",
                        unfixed_reason=SECURITY_CVE_STATUS_PENDING,
                    ),
                    UnfixedPackage(
                        pkg="pkg4",
                        unfixed_reason=SECURITY_CVE_STATUS_PENDING,
                    ),
                    UnfixedPackage(
                        pkg="pkg12",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Infra"
                        ),
                    ),
                    UnfixedPackage(
                        pkg="pkg13",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Infra"
                        ),
                    ),
                    UnfixedPackage(
                        pkg="pkg14",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Apps"
                        ),
                    ),
                    UnfixedPackage(
                        pkg="pkg15",
                        unfixed_reason=SECURITY_UA_SERVICE_REQUIRED.format(
                            service="Ubuntu Pro: ESM Apps"
                        ),
                    ),
                ],
            ),
            (  # No released version
                {
                    "pkg1": CVEPackageStatus(CVE_PKG_STATUS_IGNORED),
                    "pkg2": CVEPackageStatus(CVE_PKG_STATUS_IGNORED),
                    "pkg3": CVEPackageStatus(CVE_PKG_STATUS_PENDING),
                    "pkg4": CVEPackageStatus(CVE_PKG_STATUS_PENDING),
                    "pkg5": CVEPackageStatus(CVE_PKG_STATUS_NEEDS_TRIAGE),
                    "pkg6": CVEPackageStatus(CVE_PKG_STATUS_NEEDS_TRIAGE),
                    "pkg7": CVEPackageStatus(CVE_PKG_STATUS_NEEDED),
                    "pkg8": CVEPackageStatus(CVE_PKG_STATUS_NEEDED),
                    "pkg9": CVEPackageStatus(CVE_PKG_STATUS_DEFERRED),
                },
                {},
                {},
                ("gcp", None),
                textwrap.dedent(
                    """\
                    9 affected source packages are installed: {}
                    (1/9, 2/9, 3/9) pkg1, pkg2, pkg9:
                    Sorry, no fix is available.
                    (4/9, 5/9) pkg7, pkg8:
                    Sorry, no fix is available yet.
                    (6/9, 7/9) pkg5, pkg6:
                    Ubuntu security engineers are investigating this issue.
                    (8/9, 9/9) pkg3, pkg4:
                    A fix is coming soon. Try again tomorrow.
                    """
                ).format(
                    "pkg1, pkg2, pkg3, pkg4, pkg5, pkg6,\n"
                    "    pkg7, pkg8, pkg9"
                )
                + "\n"
                + "9 packages are still affected: {}".format(
                    "pkg1, pkg2, pkg3, pkg4, pkg5, pkg6, pkg7, pkg8,\n"
                    "    pkg9"
                )
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
                FixStatus.SYSTEM_STILL_VULNERABLE,
                [
                    UnfixedPackage(
                        pkg="pkg1",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg2",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg9",
                        unfixed_reason=SECURITY_CVE_STATUS_IGNORED,
                    ),
                    UnfixedPackage(
                        pkg="pkg7",
                        unfixed_reason=SECURITY_CVE_STATUS_NEEDED,
                    ),
                    UnfixedPackage(
                        pkg="pkg8",
                        unfixed_reason=SECURITY_CVE_STATUS_NEEDED,
                    ),
                    UnfixedPackage(
                        pkg="pkg5",
                        unfixed_reason=SECURITY_CVE_STATUS_TRIAGE,
                    ),
                    UnfixedPackage(
                        pkg="pkg6",
                        unfixed_reason=SECURITY_CVE_STATUS_TRIAGE,
                    ),
                    UnfixedPackage(
                        pkg="pkg3",
                        unfixed_reason=SECURITY_CVE_STATUS_PENDING,
                    ),
                    UnfixedPackage(
                        pkg="pkg4",
                        unfixed_reason=SECURITY_CVE_STATUS_PENDING,
                    ),
                ],
            ),
            (  # text wrapping required in several places
                {
                    "longpackagename1": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED
                    ),
                    "longpackagename2": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED
                    ),
                    "longpackagename3": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED
                    ),
                    "longpackagename4": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED
                    ),
                    "longpackagename5": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED
                    ),
                },
                {
                    "longpackagename1": {"longpackagename1": "2.0"},
                    "longpackagename2": {"longpackagename2": "2.0"},
                    "longpackagename3": {"longpackagename3": "2.0"},
                    "longpackagename4": {"longpackagename4": "2.0"},
                    "longpackagename5": {"longpackagename5": "2.0"},
                },
                {
                    "longpackagename1": {
                        "longpackagename1": {"version": "2.1"}
                    },
                    "longpackagename2": {
                        "longpackagename2": {"version": "2.1"}
                    },
                    "longpackagename3": {
                        "longpackagename3": {"version": "2.1"}
                    },
                    "longpackagename4": {
                        "longpackagename4": {"version": "2.1"}
                    },
                    "longpackagename5": {
                        "longpackagename5": {"version": "2.1"}
                    },
                },
                ("gcp", None),
                """\
5 affected source packages are installed: longpackagename1, longpackagename2,
    longpackagename3, longpackagename4, longpackagename5
(1/5, 2/5, 3/5, 4/5, 5/5) longpackagename1, longpackagename2, longpackagename3,
    longpackagename4, longpackagename5:
A fix is available in Ubuntu standard updates.\n"""
                + colorize_commands(
                    [
                        [
                            "apt update && apt install --only-upgrade"
                            " -y longpackagename1 longpackagename2 "
                            "longpackagename3 longpackagename4 "
                            "longpackagename5"
                        ]
                    ]
                )
                + "\n\n"
                + "{check} USN-### is resolved.\n".format(check=OKGREEN_CHECK),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
        ),
    )
    @mock.patch("uaclient.entitlements.base.UAEntitlement.user_facing_status")
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="c")
    def test_messages_for_affected_packages_based_on_installed_and_usn_release(
        self,
        prompt_choices,
        get_cloud_type,
        m_run_apt_cmd,
        _m_get_pkg_cand_ver,
        _m_os_getuid,
        _m_should_reboot,
        m_user_facing_status,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        cloud_type,
        expected,
        expected_ret,
        expected_unfixed_pkgs,
        FakeConfig,
        capsys,
        _subp,
    ):
        """Messaging is based on affected status and installed packages."""
        get_cloud_type.return_value = cloud_type
        m_user_facing_status.return_value = (UserFacingStatus.INACTIVE, "")
        cfg = FakeConfig()
        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                actual_ret = prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_packages,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )
                assert expected_ret == actual_ret.status
                assert expected_unfixed_pkgs == actual_ret.unfixed_pkgs
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {
                    "pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_APPS),
                    "pkg2": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                    "pkg3": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_INFRA
                    ),
                },
                {
                    "pkg1": {"pkg1": "1.8"},
                    "pkg2": {"pkg2": "1.8"},
                    "pkg3": {"pkg3": "1.8"},
                },
                {
                    "pkg1": {"pkg1": {"version": "2.0"}},
                    "pkg2": {"pkg2": {"version": "2.0"}},
                    "pkg3": {"pkg3": {"version": "2.0"}},
                },
                textwrap.dedent(
                    """\
                    3 affected source packages are installed: pkg1, pkg2, pkg3
                    (1/3) pkg2:
                    A fix is available in Ubuntu standard updates.
                    """
                )
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg2"]]
                )
                + "\n"
                + textwrap.dedent(
                    """\
                    (2/3) pkg3:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION
                + "\n"
                + PROMPT_ENTER_TOKEN
                + "\n"
                + colorize_commands([["pro attach token"]])
                + "\n"
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg3"]]
                )
                + "\n"
                + textwrap.dedent(
                    """\
                    (3/3) pkg1:
                    A fix is available in Ubuntu Pro: ESM Apps.
                    """
                )
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg1"]]
                )
                + "\n\n"
                + "{check} USN-### is resolved.\n".format(check=OKGREEN_CHECK),
            ),
        ),
    )
    @mock.patch("uaclient.util.is_config_value_true", return_value=True)
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.security._check_subscription_is_expired")
    @mock.patch("uaclient.security._check_subscription_for_required_service")
    @mock.patch("uaclient.cli.action_attach")
    @mock.patch("builtins.input", return_value="token")
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="a")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    def test_messages_for_affected_packages_covering_all_release_pockets(
        self,
        _m_apt_pkg_candidate_version,
        m_prompt_choices,
        m_get_cloud_type,
        m_run_apt_cmd,
        _m_input,
        m_action_attach,
        m_check_subscription_for_service,
        m_check_subscription_expired,
        _m_should_reboot,
        _m_is_config_value_true,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)
        m_check_subscription_for_service.return_value = True
        m_check_subscription_expired.return_value = False

        def fake_attach(args, cfg):
            cfg.for_attached_machine()
            return 0

        m_action_attach.side_effect = fake_attach

        cfg = FakeConfig()
        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_packages,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {
                    "pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                    "pkg2": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_APPS),
                    "pkg3": CVEPackageStatus(
                        CVE_PKG_STATUS_RELEASED_ESM_INFRA
                    ),
                },
                {
                    "pkg1": {"pkg1": "1.8"},
                    "pkg2": {"pkg2": "1.8"},
                    "pkg3": {"pkg3": "1.8"},
                },
                {
                    "pkg1": {"pkg1": {"version": "2.0"}},
                    "pkg2": {"pkg2": {"version": "2.0"}},
                    "pkg3": {"pkg3": {"version": "2.0"}},
                },
                textwrap.dedent(
                    """\
                    3 affected source packages are installed: pkg1, pkg2, pkg3
                    (1/3) pkg1:
                    A fix is available in Ubuntu standard updates.
                    """
                )
                + "\n"
                + "3 packages are still affected: pkg1, pkg2, pkg3"
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
            ),
        ),
    )
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.security.upgrade_packages_and_attach")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    def test_messages_for_affected_packages_when_fix_fail(
        self,
        _m_apt_pkg_candidate_version,
        m_upgrade_packages,
        _m_should_reboot,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_upgrade_packages.return_value = UpgradeResult(
            status=False, failure_reason=None
        )

        cfg = FakeConfig()
        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_packages,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {
                    "pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                    "pkg2": CVEPackageStatus(CVE_PKG_STATUS_RELEASED),
                },
                {
                    "pkg1": {"pkg1": "1.8"},
                    "pkg2": {"pkg2": "1.8"},
                },
                {
                    "pkg1": {"pkg1": {"version": "2.0"}},
                    "pkg2": {"pkg2": {"version": "1.8"}},
                },
                textwrap.dedent(
                    """\
                    2 affected source packages are installed: pkg1, pkg2
                    (1/2, 2/2) pkg1, pkg2:
                    A fix is available in Ubuntu standard updates.
                    - Cannot install package pkg1 version 2.0
                    """
                )
                + "\n"
                + "1 package is still affected: pkg1"
                + "\n"
                + "{check} CVE-### is not resolved.\n".format(check=FAIL_X),
            ),
        ),
    )
    @mock.patch("uaclient.apt.compare_versions")
    @mock.patch("uaclient.apt.get_pkg_candidate_version")
    def test_messages_for_affected_packages_when_pkg_cannot_be_upgraded(
        self,
        m_apt_pkg_candidate_version,
        m_apt_compare_versions,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_apt_pkg_candidate_version.return_value = 1.8
        m_apt_compare_versions.side_effect = [False, True, False]

        cfg = FakeConfig()
        with mock.patch("uaclient.util.sys") as m_sys:
            m_stdout = mock.MagicMock()
            type(m_sys).stdout = m_stdout
            type(m_stdout).encoding = mock.PropertyMock(return_value="utf-8")
            prompt_for_affected_packages(
                cfg=cfg,
                issue_id="CVE-###",
                affected_pkg_status=affected_pkg_status,
                installed_packages=installed_packages,
                usn_released_pkgs=usn_released_pkgs,
                dry_run=False,
            )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize("should_reboot", (False, True))
    @pytest.mark.parametrize(
        "service_status",
        (
            (UserFacingStatus.INACTIVE),
            (UserFacingStatus.INAPPLICABLE),
            (UserFacingStatus.UNAVAILABLE),
        ),
    )
    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION
                + "\n"
                + PROMPT_ENTER_TOKEN
                + "\n"
                + colorize_commands([["pro attach token"]])
                + "\n"
                + SECURITY_UA_SERVICE_NOT_ENTITLED.format(service="esm-infra")
                + "\n\n"
                + "1 package is still affected: pkg1"
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
            ),
        ),
    )
    @mock.patch("uaclient.util.is_config_value_true", return_value=True)
    @mock.patch("uaclient.system.should_reboot")
    @mock.patch("uaclient.cli.action_attach")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("builtins.input", return_value="token")
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="a")
    def test_messages_for_affected_packages_when_required_service_not_enabled(
        self,
        m_prompt_choices,
        m_get_cloud_type,
        _m_input,
        _m_apt_pkg_candidate_version,
        m_action_attach,
        m_should_reboot,
        _m_is_config_value_true,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        service_status,
        should_reboot,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_should_reboot.return_value = should_reboot
        m_get_cloud_type.return_value = ("cloud", None)

        def fake_attach(args, cfg):
            cfg.for_attached_machine()
            return 0

        m_action_attach.side_effect = fake_attach
        m_entitlement_cls = mock.MagicMock()
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.user_facing_status.return_value = (
            service_status,
            "",
        )
        m_entitlement_obj.applicability_status.return_value = (
            ApplicabilityStatus.INAPPLICABLE,
            "",
        )
        m_entitlement_obj.name = "esm-infra"

        cfg = FakeConfig()
        with mock.patch(
            "uaclient.security.entitlement_factory",
            return_value=m_entitlement_cls,
        ):
            with mock.patch("uaclient.system._subp", side_effect=_subp):
                with mock.patch("uaclient.util.sys") as m_sys:
                    m_stdout = mock.MagicMock()
                    type(m_sys).stdout = m_stdout
                    type(m_stdout).encoding = mock.PropertyMock(
                        return_value="utf-8"
                    )
                    prompt_for_affected_packages(
                        cfg=cfg,
                        issue_id="USN-###",
                        affected_pkg_status=affected_pkg_status,
                        installed_packages=installed_packages,
                        usn_released_pkgs=usn_released_pkgs,
                        dry_run=False,
                    )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_SERVICE_DISABLED.format(service="esm-infra")
                + "\n"
                + colorize_commands([["pro enable esm-infra"]])
                + "\n"
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg1"]]
                )
                + "\n\n"
                + "{check} USN-### is resolved.\n".format(check=OKGREEN_CHECK),
            ),
        ),
    )
    @mock.patch("uaclient.security._is_pocket_used_by_beta_service")
    @mock.patch("uaclient.util.is_config_value_true", return_value=False)
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.security._check_subscription_is_expired")
    @mock.patch("uaclient.cli.action_enable", return_value=0)
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="e")
    def test_messages_for_affected_packages_when_service_can_be_enabled(
        self,
        m_prompt_choices,
        m_get_cloud_type,
        _m_os_getuid,
        _m_apt_pkg_candidate_version,
        _m_run_apt,
        m_action_enable,
        m_check_subscription_expired,
        _m_should_reboot,
        _m_is_config_value_true,
        m_is_pocket_beta_service,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)
        m_check_subscription_expired.return_value = False
        m_is_pocket_beta_service.return_value = False

        m_entitlement_cls = mock.MagicMock()
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.user_facing_status.return_value = (
            UserFacingStatus.INACTIVE,
            "",
        )
        m_entitlement_obj.applicability_status.return_value = (
            ApplicabilityStatus.APPLICABLE,
            "",
        )
        type(m_entitlement_obj).name = mock.PropertyMock(
            return_value="esm-infra"
        )

        cfg = FakeConfig().for_attached_machine()
        with mock.patch(
            "uaclient.entitlements.entitlement_factory",
            return_value=m_entitlement_cls,
        ):
            with mock.patch("uaclient.system._subp", side_effect=_subp):
                with mock.patch("uaclient.util.sys") as m_sys:
                    m_stdout = mock.MagicMock()
                    type(m_sys).stdout = m_stdout
                    type(m_stdout).encoding = mock.PropertyMock(
                        return_value="utf-8"
                    )
                    prompt_for_affected_packages(
                        cfg=cfg,
                        issue_id="USN-###",
                        affected_pkg_status=affected_pkg_status,
                        installed_packages=installed_packages,
                        usn_released_pkgs=usn_released_pkgs,
                        dry_run=False,
                    )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_SERVICE_DISABLED.format(service="esm-infra")
                + "\n"
                + SECURITY_UA_SERVICE_NOT_ENABLED.format(service="esm-infra")
                + "\n\n"
                + "1 package is still affected: pkg1"
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
            ),
        ),
    )
    @mock.patch("uaclient.security._is_pocket_used_by_beta_service")
    @mock.patch("uaclient.util.is_config_value_true", return_value=False)
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.security._check_subscription_is_expired")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="c")
    def test_messages_for_affected_packages_when_service_kept_disabled(
        self,
        m_prompt_choices,
        m_get_cloud_type,
        _m_os_getuid,
        _m_apt_pkg_candidate_version,
        m_check_subscription_expired,
        _m_should_reboot,
        _m_is_config_value_true,
        m_is_pocket_beta_service,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)
        m_check_subscription_expired.return_value = False
        m_is_pocket_beta_service.return_value = False

        m_entitlement_cls = mock.MagicMock()
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.user_facing_status.return_value = (
            UserFacingStatus.INACTIVE,
            "",
        )
        m_entitlement_obj.applicability_status.return_value = (
            ApplicabilityStatus.APPLICABLE,
            "",
        )
        type(m_entitlement_obj).name = mock.PropertyMock(
            return_value="esm-infra"
        )

        cfg = FakeConfig().for_attached_machine()
        with mock.patch(
            "uaclient.entitlements.entitlement_factory",
            return_value=m_entitlement_cls,
        ):
            with mock.patch("uaclient.system._subp", side_effect=_subp):
                with mock.patch("uaclient.util.sys") as m_sys:
                    m_stdout = mock.MagicMock()
                    type(m_sys).stdout = m_stdout
                    type(m_stdout).encoding = mock.PropertyMock(
                        return_value="utf-8"
                    )
                    prompt_for_affected_packages(
                        cfg=cfg,
                        issue_id="USN-###",
                        affected_pkg_status=affected_pkg_status,
                        installed_packages=installed_packages,
                        usn_released_pkgs=usn_released_pkgs,
                        dry_run=False,
                    )
        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_UPDATE_NOT_INSTALLED_EXPIRED
                + "\n"
                + PROMPT_EXPIRED_ENTER_TOKEN
                + "\n"
                + colorize_commands([["pro detach"]])
                + "\n"
                + colorize_commands([["pro attach token"]])
                + "\n"
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg1"]]
                )
                + "\n\n"
                + "{check} USN-### is resolved.\n".format(check=OKGREEN_CHECK),
            ),
        ),
    )
    @mock.patch("uaclient.security._is_pocket_used_by_beta_service")
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("uaclient.cli.action_attach")
    @mock.patch("builtins.input", return_value="token")
    @mock.patch("uaclient.cli.action_detach")
    @mock.patch("uaclient.security._check_subscription_for_required_service")
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="r")
    def test_messages_for_affected_packages_when_subscription_expired(
        self,
        m_prompt_choices,
        m_get_cloud_type,
        m_check_subscription_for_service,
        _m_cli_detach,
        _m_input,
        m_cli_attach,
        _m_apt_pkg_candidate_version,
        _m_run_apt_command,
        _m_should_reboot,
        m_is_pocket_beta_service,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)
        m_check_subscription_for_service.return_value = True
        m_cli_attach.return_value = 0
        m_is_pocket_beta_service.return_value = False

        cfg = FakeConfig().for_attached_machine(
            status_cache={
                "expires": "1999-12-01T00:00:00Z",
                "attached": True,
            },
        )
        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_packages,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )

        out, err = capsys.readouterr()
        assert expected == out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED_ESM_INFRA)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu Pro: ESM Infra.
                    """
                )
                + SECURITY_UPDATE_NOT_INSTALLED_EXPIRED
                + "\n\n"
                + "1 package is still affected: pkg1"
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
            ),
        ),
    )
    @mock.patch("uaclient.security._is_pocket_used_by_beta_service")
    @mock.patch("uaclient.system.should_reboot", return_value=False)
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="c")
    def test_messages_for_affected_packages_when_subscription_not_renewed(
        self,
        m_prompt_choices,
        m_get_cloud_type,
        _m_os_getuid,
        _m_apt_pkg_candidate_version,
        _m_should_reboot,
        m_is_pocket_beta_service,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)
        m_is_pocket_beta_service.return_value = False

        cfg = FakeConfig().for_attached_machine(
            status_cache={
                "expires": "1999-12-01T00:00:00Z",
                "attached": True,
            },
        )

        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_packages,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )

        out, err = capsys.readouterr()
        assert expected in out

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_pkgs,usn_released_pkgs,exp_msg,exp_ret",
        (
            (
                {"pkg1": CVEPackageStatus(CVE_PKG_STATUS_RELEASED)},
                {"pkg1": {"pkg1": "1.8"}},
                {"pkg1": {"pkg1": {"version": "2.0"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: pkg1
                    (1/1) pkg1:
                    A fix is available in Ubuntu standard updates.
                    """
                )
                + colorize_commands(
                    [["apt update && apt install --only-upgrade" " -y pkg1"]]
                )
                + "\n\n"
                + "A reboot is required to complete fix operation."
                + "\n"
                + "{check} USN-### is not resolved.\n".format(check=FAIL_X),
                FixStatus.SYSTEM_VULNERABLE_UNTIL_REBOOT,
            ),
        ),
    )
    @mock.patch("uaclient.files.notices.NoticesManager.add")
    @mock.patch("uaclient.system.should_reboot", return_value=True)
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.get_cloud_type")
    def test_messages_for_affected_packages_when_reboot_required(
        self,
        m_get_cloud_type,
        _m_os_getuid,
        _m_apt_pkg_candidate_version,
        _m_run_apt_command,
        _m_should_reboot,
        m_add_notice,
        affected_pkg_status,
        installed_pkgs,
        usn_released_pkgs,
        exp_msg,
        exp_ret,
        FakeConfig,
        capsys,
        _subp,
    ):
        m_get_cloud_type.return_value = ("cloud", None)

        cfg = FakeConfig()
        with mock.patch("uaclient.system._subp", side_effect=_subp):
            with mock.patch("uaclient.util.sys") as m_sys:
                m_stdout = mock.MagicMock()
                type(m_sys).stdout = m_stdout
                type(m_stdout).encoding = mock.PropertyMock(
                    return_value="utf-8"
                )
                actual_ret = prompt_for_affected_packages(
                    cfg=cfg,
                    issue_id="USN-###",
                    affected_pkg_status=affected_pkg_status,
                    installed_packages=installed_pkgs,
                    usn_released_pkgs=usn_released_pkgs,
                    dry_run=False,
                )
                assert exp_ret == actual_ret.status
        out, err = capsys.readouterr()
        assert exp_msg in out

        assert [
            mock.call(
                Notice.ENABLE_REBOOT_REQUIRED,
                ENABLE_REBOOT_REQUIRED_TMPL.format(operation="fix operation"),
            )
        ] == m_add_notice.call_args_list

    @pytest.mark.parametrize(
        "affected_pkg_status,installed_packages,usn_released_pkgs,expected",
        (
            (
                {"slsrc": CVEPackageStatus(CVE_PKG_STATUS_RELEASED)},
                {"slsrc": {"sl": "2.1"}},
                {"slsrc": {"sl": {"version": "2.1"}}},
                textwrap.dedent(
                    """\
                    1 affected source package is installed: slsrc
                    (1/1) slsrc:
                    A fix is available in Ubuntu standard updates.
                    The update is already installed.

                    {check} USN-### is resolved.
                    """.format(
                        check=OKGREEN_CHECK  # noqa: E126
                    )  # noqa: E126
                ),
            ),
        ),
    )
    @mock.patch("uaclient.files.notices.NoticesManager.add")
    @mock.patch("uaclient.system.should_reboot", return_value=True)
    @mock.patch("uaclient.apt.run_apt_command", return_value="")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.get_cloud_type")
    def test_messages_for_affected_packages_when_reboot_required_but_update_already_installed(  # noqa: E501
        self,
        m_get_cloud_type,
        _m_os_getuid,
        _m_apt_pkg_candidate_version,
        _m_run_apt_command,
        _m_should_reboot,
        m_add_notice,
        affected_pkg_status,
        installed_packages,
        usn_released_pkgs,
        expected,
        FakeConfig,
        capsys,
    ):
        m_get_cloud_type.return_value = ("cloud", None)

        cfg = FakeConfig()
        with mock.patch("uaclient.util.sys") as m_sys:
            m_stdout = mock.MagicMock()
            type(m_sys).stdout = m_stdout
            type(m_stdout).encoding = mock.PropertyMock(return_value="utf-8")
            prompt_for_affected_packages(
                cfg=cfg,
                issue_id="USN-###",
                affected_pkg_status=affected_pkg_status,
                installed_packages=installed_packages,
                usn_released_pkgs=usn_released_pkgs,
                dry_run=False,
            )
        out, err = capsys.readouterr()
        assert expected in out


class TestUpgradePackagesAndAttach:
    @pytest.mark.parametrize("root", ((True), (False)))
    @mock.patch("uaclient.util.we_are_currently_root")
    @mock.patch("uaclient.security.system.subp")
    def test_upgrade_packages_are_installed_without_need_for_ua(
        self, m_subp, m_we_are_currently_root, root, capsys
    ):
        m_subp.return_value = ("", "")
        m_we_are_currently_root.return_value = root

        upgrade_packages_and_attach(
            cfg=None,
            upgrade_pkgs=["t1", "t2"],
            pocket="Ubuntu standard updates",
            dry_run=False,
        )

        out, err = capsys.readouterr()
        if root:
            assert m_subp.call_count == 2
            assert "apt update" in out
            assert "apt install --only-upgrade -y t1 t2" in out
        else:
            assert SECURITY_APT_NON_ROOT in out
            assert m_subp.call_count == 0

    @pytest.mark.parametrize(
        "exception, expected_error_msg",
        (
            (Exception("base-exception"), "base-exception"),
            (fakes.FakeUbuntuProError(), "This is a test"),
        ),
    )
    @mock.patch("os.getuid", return_value=0)
    @mock.patch("uaclient.security.system.subp")
    def test_upgrade_packages_fail_if_apt_command_fails(
        self, m_subp, m_os_getuid, exception, expected_error_msg, capsys
    ):
        m_subp.side_effect = exception
        assert (
            upgrade_packages_and_attach(
                cfg=None,
                upgrade_pkgs=["t1=123"],
                pocket="Ubuntu standard updates",
                dry_run=False,
            ).status
            is False
        )

        out, _ = capsys.readouterr()
        assert expected_error_msg in out


class TestFixSecurityIssueId:
    @pytest.mark.parametrize(
        "issue_id,livepatch_status,exp_ret",
        (
            (
                "cve-2013-1798",
                livepatch.LivepatchStatusStatus(
                    kernel="4.4.0-210.242-generic",
                    supported=None,
                    livepatch=livepatch.LivepatchPatchStatus(
                        state="applied",
                        version="87.1",
                        fixes=[
                            livepatch.LivepatchPatchFixStatus(
                                name="cve-2013-1798", patched=True
                            )
                        ],
                    ),
                ),
                FixStatus.SYSTEM_NON_VULNERABLE,
            ),
        ),
    )
    @mock.patch("uaclient.livepatch.status")
    def test_patched_msg_when_issue_id_fixed_by_livepatch(
        self,
        m_livepatch_status,
        issue_id,
        livepatch_status,
        exp_ret,
        FakeConfig,
    ):
        """fix_security_id returns system not vulnerable when issue_id fixed
        by livepatch"""
        m_livepatch_status.return_value = livepatch_status
        with mock.patch(
            "uaclient.security.query_installed_source_pkg_versions"
        ):
            assert exp_ret == fix_security_issue_id(FakeConfig(), issue_id)

    @pytest.mark.parametrize("error_code", ((404), (400)))
    @pytest.mark.parametrize(
        "issue_id", (("CVE-1800-123456"), ("USN-12345-12"))
    )
    @mock.patch("uaclient.security.query_installed_source_pkg_versions")
    def test_error_msg_when_issue_id_is_not_found(
        self, _m_query_versions, issue_id, error_code, FakeConfig
    ):
        expected_message = "Error: {} not found.".format(issue_id)
        if "CVE" in issue_id:
            mock_func = "get_cve"
            issue_type = "CVE"
        else:
            mock_func = "get_notice"
            issue_type = "USN"

        with mock.patch.object(UASecurityClient, mock_func) as m_func:
            msg = "{} with id 'ID' does not exist".format(issue_type)

            m_func.side_effect = exceptions.SecurityAPIError(
                url="URL", code=error_code, body=json.dumps({"message": msg})
            )

            with pytest.raises(exceptions.UbuntuProError) as exc:
                fix_security_issue_id(FakeConfig(), issue_id)

        if error_code == 404:
            expected_message = "Error: {} not found.".format(issue_id)
        else:
            expected_message = (
                "Error connecting to URL: "
                + str(error_code)
                + " "
                + json.dumps({"message": msg})
            )

        assert expected_message == exc.value.msg

    @mock.patch("uaclient.security.query_installed_source_pkg_versions")
    @mock.patch(
        "uaclient.api.u.pro.security.fix.get_usn_affected_packages_status"
    )  # noqa
    @mock.patch("uaclient.security.merge_usn_released_binary_package_versions")
    def test_error_msg_when_usn_does_not_have_any_related_usns(
        self,
        m_merge_usn,
        m_usn_affected_pkgs,
        m_query_installed_pkgs,
        FakeConfig,
    ):
        m_query_installed_pkgs.return_value = {}
        m_usn_affected_pkgs.return_value = {}
        m_merge_usn.return_value = {}
        with mock.patch.object(UASecurityClient, "get_notice") as m_notice:
            with mock.patch.object(
                UASecurityClient, "get_notices"
            ) as m_notices:
                usn_mock = mock.MagicMock()
                cve_mock = mock.MagicMock()

                type(cve_mock).notices_ids = mock.PropertyMock(
                    return_value=["USN-123"]
                )
                type(usn_mock).cves = mock.PropertyMock(
                    return_value=[cve_mock]
                )
                type(usn_mock).response = mock.PropertyMock(
                    return_value={"release_packages": {}}
                )
                type(usn_mock).cves_ids = mock.PropertyMock(
                    return_value=["cve-123"]
                )
                type(usn_mock).id = mock.PropertyMock(return_value="id")

                m_notice.return_value = usn_mock
                m_notices.return_value = [usn_mock]

                with pytest.raises(exceptions.SecurityAPIMetadataError) as exc:
                    fix_security_issue_id(FakeConfig(), "USN-123")

        expected_msg = (
            "Error: USN-123 metadata defines no fixed package versions."
        )
        assert expected_msg in exc.value.msg


class TestMergeUSNReleasedBinaryPackageVersions:
    @pytest.mark.parametrize(
        "usns_released_packages, expected_pkgs_dict",
        (
            ([{}], {}),
            (
                [{"pkg1": {"libpkg1": {"version": "1.0", "name": "libpkg1"}}}],
                {"pkg1": {"libpkg1": {"version": "1.0", "name": "libpkg1"}}},
            ),
            (
                [
                    {
                        "pkg1": {
                            "libpkg1": {"version": "1.0", "name": "libpkg1"}
                        },
                        "pkg2": {
                            "libpkg2": {"version": "2.0", "name": "libpkg2"},
                            "libpkg3": {"version": "3.0", "name": "libpkg3"},
                            "libpkg4": {"version": "3.0", "name": "libpkg4"},
                        },
                    },
                    {
                        "pkg2": {
                            "libpkg2": {"version": "1.8", "name": "libpkg2"},
                            "libpkg4": {"version": "3.2", "name": "libpkg4"},
                        }
                    },
                ],
                {
                    "pkg1": {"libpkg1": {"version": "1.0", "name": "libpkg1"}},
                    "pkg2": {
                        "libpkg2": {"version": "2.0", "name": "libpkg2"},
                        "libpkg3": {"version": "3.0", "name": "libpkg3"},
                        "libpkg4": {"version": "3.2", "name": "libpkg4"},
                    },
                },
            ),
            (
                [
                    {
                        "pkg1": {
                            "libpkg1": {"version": "1.0", "name": "libpkg1"},
                            "source": {"version": "2.0", "name": "pkg1"},
                        }
                    },
                    {"pkg1": {"source": {"version": "2.5", "name": "pkg1"}}},
                ],
                {
                    "pkg1": {
                        "libpkg1": {"version": "1.0", "name": "libpkg1"},
                        "source": {"version": "2.5", "name": "pkg1"},
                    }
                },
            ),
            (
                [
                    {
                        "pkg1": {
                            "libpkg1": {"version": "1.0", "name": "libpkg1"},
                            "source": {"version": "2.0", "name": "pkg1"},
                        },
                        "pkg2": {
                            "libpkg2": {
                                "version": "2.0",
                                "name": "libpkg2",
                                "pocket": "esm-apps",
                            },
                            "source": {
                                "version": "2.0",
                                "name": "pkg2",
                                "pocket": "esm-apps",
                            },
                        },
                    }
                ],
                {
                    "pkg1": {
                        "libpkg1": {"version": "1.0", "name": "libpkg1"},
                        "source": {"version": "2.0", "name": "pkg1"},
                    }
                },
            ),
        ),
    )
    def test_merge_usn_released_binary_package_versions(
        self, usns_released_packages, expected_pkgs_dict, _subp
    ):
        usns = []
        beta_packages = {"esm-infra": False, "esm-apps": True}

        for usn_released_pkgs in usns_released_packages:
            usn = mock.MagicMock()
            type(usn).release_packages = mock.PropertyMock(
                return_value=usn_released_pkgs
            )
            usns.append(usn)

        with mock.patch("uaclient.system._subp", side_effect=_subp):
            usn_pkgs_dict = merge_usn_released_binary_package_versions(
                usns, beta_packages
            )
        assert expected_pkgs_dict == usn_pkgs_dict


class TestCheckAttached:
    def test_check_attached_print_message_and_succeed_on_dry_run(
        self,
        FakeConfig,
        capsys,
    ):
        cfg = FakeConfig()
        assert _check_attached(cfg, dry_run=True)

        out, _ = capsys.readouterr()
        assert SECURITY_DRY_RUN_UA_NOT_ATTACHED in out


class TestCheckSubscriptionForRequiredService:
    @mock.patch("uaclient.security._get_service_for_pocket")
    def test_check_subscription_print_message_and_succeed_on_dry_run(
        self,
        m_get_service,
        FakeConfig,
        capsys,
    ):
        ent_mock = mock.MagicMock()
        ent_mock.user_facing_status.return_value = (
            UserFacingStatus.INACTIVE,
            None,
        )
        ent_mock.applicability_status.return_value = (
            ApplicabilityStatus.APPLICABLE,
            None,
        )
        type(ent_mock).name = mock.PropertyMock(return_value="test")

        m_get_service.return_value = ent_mock
        cfg = FakeConfig()
        assert _check_subscription_for_required_service(
            pocket="", cfg=cfg, dry_run=True
        )

        out, _ = capsys.readouterr()
        assert (
            SECURITY_DRY_RUN_UA_SERVICE_NOT_ENABLED.format(service="test")
            in out
        )

    @mock.patch("uaclient.security._get_service_for_pocket")
    def test_check_subscription_when_service_enabled(
        self, m_get_service, FakeConfig
    ):
        ent_mock = mock.MagicMock()
        ent_mock.user_facing_status.return_value = (
            UserFacingStatus.ACTIVE,
            None,
        )

        m_get_service.return_value = ent_mock
        cfg = FakeConfig()
        assert _check_subscription_for_required_service(
            pocket="", cfg=cfg, dry_run=False
        )


class TestPromptForAttach:
    @mock.patch("uaclient.security._initiate")
    @mock.patch("uaclient.security._wait")
    @mock.patch("uaclient.security._revoke")
    @mock.patch("uaclient.security._inform_ubuntu_pro_existence_if_applicable")
    @mock.patch("uaclient.util.prompt_choices")
    def test_magic_attach_revoke_token_if_wait_fails(
        self,
        m_prompt_choices,
        _m_inform_pro,
        m_revoke,
        m_wait,
        m_initiate,
        FakeConfig,
    ):
        m_prompt_choices.return_value = "s"
        m_initiate.return_value = mock.MagicMock(
            token="token", user_code="user_code"
        )
        m_wait.side_effect = exceptions.MagicAttachTokenError()

        with pytest.raises(exceptions.MagicAttachTokenError):
            _prompt_for_attach(cfg=FakeConfig())

        assert 1 == m_initiate.call_count
        assert 1 == m_wait.call_count
        assert 1 == m_revoke.call_count


class TestFixUSN:
    @mock.patch("uaclient.security._check_attached", return_value=False)
    @mock.patch("uaclient.apt.compare_versions")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("uaclient.security.merge_usn_released_binary_package_versions")
    @mock.patch("uaclient.security.get_affected_packages_from_usn")
    def test_fix_usn_with_related_usns(
        self,
        m_affected_pkgs,
        m_merge_usn,
        _m_get_pkg_cand_ver,
        m_compare_versions,
        _m_check_attached,
        capsys,
        FakeConfig,
    ):
        usn = mock.MagicMock()
        issue_id = "USN-123"
        related_usns = [
            mock.MagicMock(id="USN-456"),
            mock.MagicMock(id="USN-789"),
            mock.MagicMock(id="USN-822"),
        ]
        installed_packages = {
            "pkg1": {"pkg1": "1.0"},
            "pkg2": {"pkg2": "1.0"},
            "pkg3": {"pkg3": "1.0"},
            "pkg4": {"pkg4": "1.0"},
            "pkg5": {"pkg5": "1.0"},
        }
        cfg = FakeConfig()
        beta_pockets = {}
        dry_run = False
        no_related = False

        m_affected_pkgs.side_effect = [
            {
                "pkg1": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "security",
                    }
                )
            },
            {
                "pkg2": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-infra",
                    }
                )
            },
            {
                "pkg3": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-apps",
                    }
                ),
                "pkg4": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-apps",
                    }
                ),
            },
            {
                "pkg5": CVEPackageStatus(
                    {
                        "status": "pending",
                        "pocket": "security",
                    }
                )
            },
        ]
        m_merge_usn.side_effect = [
            {
                "pkg1": {"pkg1": {"version": "1.2", "name": "pkg1"}},
            },
            {
                "pkg2": {"pkg2": {"version": "1.2", "name": "pkg2"}},
            },
            {
                "pkg3": {"pkg3": {"version": "1.2", "name": "pkg3"}},
                "pkg4": {"pkg4": {"version": "1.2", "name": "pkg4"}},
            },
            {
                "pkg5": {"pkg5": {"version": "1.2", "name": "pkg5"}},
            },
        ]

        m_compare_versions.side_effect = [
            False,
            True,
            False,
            True,
            False,
            False,
            True,
            True,
            False,
            True,
        ]

        with mock.patch("uaclient.util.sys") as m_sys:
            m_stdout = mock.MagicMock()
            type(m_sys).stdout = m_stdout
            type(m_stdout).encoding = mock.PropertyMock(return_value="utf-8")
            actual_ret = _fix_usn(
                usn=usn,
                related_usns=related_usns,
                issue_id=issue_id,
                installed_packages=installed_packages,
                cfg=cfg,
                beta_pockets=beta_pockets,
                dry_run=dry_run,
                no_related=no_related,
            )

        expected_msg = (
            "\n"
            + SECURITY_FIXING_REQUESTED_USN.format(issue_id=issue_id)
            + "\n"
            + textwrap.dedent(
                """\
                1 affected source package is installed: pkg1
                (1/1) pkg1:
                A fix is available in Ubuntu standard updates.
                """
            )
            + colorize_commands(
                [["apt update && apt install --only-upgrade" " -y pkg1"]]
            )
            + "\n\n"
            + "{check} USN-123 is resolved.\n".format(check=OKGREEN_CHECK)
            + "\n"
            + textwrap.dedent(
                """\
                Found related USNs:
                - USN-456
                - USN-789
                - USN-822
                """
            )
            + "\n"
            + textwrap.dedent(
                """\
                Fixing related USNs:
                - USN-456
                1 affected source package is installed: pkg2
                (1/1) pkg2:
                A fix is available in Ubuntu Pro: ESM Infra.
                """
            )
            + "\n"
            + "1 package is still affected: pkg2"
            + "\n"
            + "{check} USN-456 is not resolved.".format(check=FAIL_X)
            + "\n\n"
            + textwrap.dedent(
                """\
                - USN-789
                2 affected source packages are installed: pkg3, pkg4
                (1/2, 2/2) pkg3, pkg4:
                A fix is available in Ubuntu Pro: ESM Apps.
                """
            )
            + "\n"
            + "2 packages are still affected: pkg3, pkg4"
            + "\n"
            + "{check} USN-789 is not resolved.".format(check=FAIL_X)
            + "\n\n"
            + textwrap.dedent(
                """\
                - USN-822
                1 affected source package is installed: pkg5
                (1/1) pkg5:
                A fix is coming soon. Try again tomorrow.
                """
            )
            + "\n"
            + "1 package is still affected: pkg5"
            + "\n"
            + "{check} USN-822 is not resolved.".format(check=FAIL_X)
            + "\n\n"
            + "Summary:"
            + "\n"
            + "{check} USN-123 [requested] is resolved.".format(
                check=OKGREEN_CHECK
            )
            + "\n"
            + "{check} USN-456 [related] is not resolved.".format(check=FAIL_X)
            + "\n"
            + "  - pkg2: Ubuntu Pro: ESM Infra is required for upgrade."
            + "\n"
            + "{check} USN-789 [related] is not resolved.".format(check=FAIL_X)
            + "\n"
            + "  - pkg3: Ubuntu Pro: ESM Apps is required for upgrade."
            + "\n"
            + "  - pkg4: Ubuntu Pro: ESM Apps is required for upgrade."
            + "\n"
            + "{check} USN-822 [related] is not resolved.".format(check=FAIL_X)
            + "\n"
            + "  - pkg5: A fix is coming soon. Try again tomorrow."
            + "\n\n"
            + SECURITY_RELATED_USN_ERROR.format(issue_id="USN-123")
        )
        out, err = capsys.readouterr()
        assert expected_msg in out
        assert FixStatus.SYSTEM_NON_VULNERABLE == actual_ret

    @mock.patch("uaclient.apt.compare_versions")
    @mock.patch("uaclient.apt.get_pkg_candidate_version", return_value="99.9")
    @mock.patch("uaclient.security.merge_usn_released_binary_package_versions")
    @mock.patch("uaclient.security.get_affected_packages_from_usn")
    def test_fix_usn_when_no_related_value_is_true(
        self,
        m_affected_pkgs,
        m_merge_usn,
        _m_get_pkg_cand_ver,
        m_compare_versions,
        capsys,
        FakeConfig,
    ):
        usn = mock.MagicMock()
        issue_id = "USN-123"
        related_usns = [
            mock.MagicMock(id="USN-456"),
            mock.MagicMock(id="USN-789"),
            mock.MagicMock(id="USN-822"),
        ]
        installed_packages = {
            "pkg1": {"pkg1": "1.0"},
            "pkg2": {"pkg2": "1.0"},
            "pkg3": {"pkg3": "1.0"},
            "pkg4": {"pkg4": "1.0"},
            "pkg5": {"pkg5": "1.0"},
        }
        cfg = FakeConfig()
        beta_pockets = {}
        dry_run = False
        no_related = True

        m_affected_pkgs.side_effect = [
            {
                "pkg1": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "security",
                    }
                )
            },
            {
                "pkg2": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-infra",
                    }
                )
            },
            {
                "pkg3": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-apps",
                    }
                ),
                "pkg4": CVEPackageStatus(
                    {
                        "status": "released",
                        "pocket": "esm-apps",
                    }
                ),
            },
            {
                "pkg5": CVEPackageStatus(
                    {
                        "status": "pending",
                        "pocket": "security",
                    }
                )
            },
        ]
        m_merge_usn.side_effect = [
            {
                "pkg1": {"pkg1": {"version": "1.2", "name": "pkg1"}},
            },
        ]

        m_compare_versions.side_effect = [
            False,
            True,
        ]

        with mock.patch("uaclient.util.sys") as m_sys:
            m_stdout = mock.MagicMock()
            type(m_sys).stdout = m_stdout
            type(m_stdout).encoding = mock.PropertyMock(return_value="utf-8")
            actual_ret = _fix_usn(
                usn=usn,
                related_usns=related_usns,
                issue_id=issue_id,
                installed_packages=installed_packages,
                cfg=cfg,
                beta_pockets=beta_pockets,
                dry_run=dry_run,
                no_related=no_related,
            )

        expected_msg = (
            "\n"
            + SECURITY_FIXING_REQUESTED_USN.format(issue_id=issue_id)
            + "\n"
            + textwrap.dedent(
                """\
                1 affected source package is installed: pkg1
                (1/1) pkg1:
                A fix is available in Ubuntu standard updates.
                """
            )
            + colorize_commands(
                [["apt update && apt install --only-upgrade" " -y pkg1"]]
            )
        )
        out, err = capsys.readouterr()
        assert expected_msg in out
        assert FixStatus.SYSTEM_NON_VULNERABLE == actual_ret
