import contextlib
import io
import textwrap

import mock
import pytest

from uaclient import exceptions, messages
from uaclient.api.u.pro.security.fix import FixStatus
from uaclient.api.u.pro.security.fix.common.plan.v1 import (
    ESM_INFRA_POCKET,
    STANDARD_UPDATES_POCKET,
    AptUpgradeData,
    AttachData,
    EnableData,
    FixPlanAptUpgradeStep,
    FixPlanAttachStep,
    FixPlanEnableStep,
    FixPlanNoOpStatus,
    FixPlanNoOpStep,
    FixPlanResult,
    FixPlanUSNResult,
    NoOpData,
    USNAdditionalData,
)
from uaclient.cli import main
from uaclient.cli.fix import (
    action_fix,
    execute_fix_plan,
    print_cve_header,
    print_usn_header,
)
from uaclient.status import colorize_commands

M_PATH = "uaclient.cli."

HELP_OUTPUT = textwrap.dedent(
    """\
usage: pro fix <CVE-yyyy-nnnn+>|<USN-nnnn-d+> [flags]

Inspect and resolve CVEs and USNs (Ubuntu Security Notices) on this machine.

positional arguments:
  security_issue  Security vulnerability ID to inspect and resolve on this
                  system. Format: CVE-yyyy-nnnn, CVE-yyyy-nnnnnnn or USN-nnnn-
                  dd

Flags:
  -h, --help      show this help message and exit
  --dry-run       If used, fix will not actually run but will display
                  everything that will happen on the machine during the
                  command.
  --no-related    If used, when fixing a USN, the command will not try to also
                  fix related USNs to the target USN.
"""
)


class TestActionFix:
    @mock.patch("uaclient.cli.setup_logging")
    @mock.patch("uaclient.cli.contract.get_available_resources")
    def test_fix_help(
        self, _m_resources, _m_setup_logging, capsys, FakeConfig
    ):
        with pytest.raises(SystemExit):
            with mock.patch("sys.argv", ["/usr/bin/ua", "fix", "--help"]):
                with mock.patch(
                    "uaclient.config.UAConfig",
                    return_value=FakeConfig(),
                ):
                    main()
        out, _err = capsys.readouterr()
        assert HELP_OUTPUT == out

    @pytest.mark.parametrize(
        "issue,is_valid",
        (
            ("CVE-2020-1234", True),
            ("cve-2020-12345", True),
            ("cve-1234-123456", True),
            ("CVE-2020-1234567", True),
            ("USN-1234-1", True),
            ("usn-1234-12", True),
            ("USN-12345-1", True),
            ("usn-12345-12", True),
            ("lsn-1234-1", True),
            ("LSN-1234-12", True),
            ("LSN-1234-123", False),
            ("cve-1234-123", False),
            ("CVE-1234-12345678", False),
            ("USA-1234-12345678", False),
        ),
    )
    @mock.patch("uaclient.cli.fix.fix_cve")
    @mock.patch("uaclient.cli.fix.fix_usn")
    def test_attached(self, m_fix_cve, m_fix_usn, issue, is_valid, FakeConfig):
        """Check that root and non-root will emit attached status"""
        cfg = FakeConfig()
        args = mock.MagicMock(
            security_issue=issue, dry_run=False, no_related=False
        )
        m_fix_cve.return_value = FixStatus.SYSTEM_NON_VULNERABLE
        m_fix_usn.return_value = FixStatus.SYSTEM_NON_VULNERABLE
        if is_valid:
            assert 0 == action_fix(args, cfg=cfg)
        else:
            with pytest.raises(exceptions.UbuntuProError) as excinfo:
                action_fix(args, cfg=cfg)

            expected_msg = (
                'Error: issue "{}" is not recognized.\n'
                'Usage: "pro fix CVE-yyyy-nnnn" or "pro fix USN-nnnn"'
            ).format(issue)

            assert expected_msg == str(excinfo.value)
            assert 0 == m_fix_cve.call_count
            assert 0 == m_fix_usn.call_count

    def test_cve_header(self):
        cve = FixPlanResult(
            title="CVE-2020-1472",
            description="Samba vulnerability",
            expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,
            affected_packages=["pkg1", "pkg2"],
            plan=[],
            warnings=None,
            error=None,
            additional_data=None,
        )

        fake_stdout = io.StringIO()
        with contextlib.redirect_stdout(fake_stdout):
            print_cve_header(cve)

        assert (
            textwrap.dedent(
                """\
                CVE-2020-1472: Samba vulnerability
                 - https://ubuntu.com/security/CVE-2020-1472"""
            )
            == fake_stdout.getvalue().strip()
        )

    @pytest.mark.parametrize(
        "usn,expected_output",
        (
            (
                FixPlanUSNResult(
                    target_usn_plan=FixPlanResult(
                        title="USN-4510-2",
                        description="Samba vulnerability",
                        expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,  # noqa
                        affected_packages=["pkg1", "pkg2"],
                        plan=[],
                        warnings=None,
                        error=None,
                        additional_data=USNAdditionalData(
                            associated_cves=["CVE-2020-1473", "CVE-2020-1472"],
                            associated_launchpad_bugs=[],
                        ),
                    ),
                    related_usns_plan=[],
                ),
                textwrap.dedent(
                    """\
                    USN-4510-2: Samba vulnerability
                    Found CVEs:
                     - https://ubuntu.com/security/CVE-2020-1473
                     - https://ubuntu.com/security/CVE-2020-1472"""
                ),
            ),
            (
                FixPlanUSNResult(
                    target_usn_plan=FixPlanResult(
                        title="USN-4038-3",
                        description="USN vulnerability",
                        expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,  # noqa
                        affected_packages=["pkg1", "pkg2"],
                        plan=[],
                        warnings=None,
                        error=None,
                        additional_data=USNAdditionalData(
                            associated_cves=[],
                            associated_launchpad_bugs=[
                                "https://launchpad.net/bugs/1834494"
                            ],
                        ),
                    ),
                    related_usns_plan=[],
                ),
                textwrap.dedent(
                    """\
                    USN-4038-3: USN vulnerability
                    Found Launchpad bugs:
                     - https://launchpad.net/bugs/1834494"""
                ),
            ),
        ),
    )
    def test_usn_header(self, usn, expected_output):
        fake_stdout = io.StringIO()
        with contextlib.redirect_stdout(fake_stdout):
            print_usn_header(usn)
        assert expected_output == fake_stdout.getvalue().strip()


class TestExecuteFixPlan:
    @pytest.mark.parametrize(
        "fix_plan,dry_run,cloud_type,expected_output,expected_fix_status,"
        "expected_unfixed_pkgs",
        (
            (  # No affected_packages listed
                FixPlanResult(
                    title="USN-###",
                    description="test",
                    expected_status=FixStatus.SYSTEM_NOT_AFFECTED.value.msg,
                    affected_packages=[],
                    plan=[
                        FixPlanNoOpStep(
                            data=NoOpData(
                                status=FixPlanNoOpStatus.NOT_AFFECTED.value
                            ),
                            order=1,
                        )
                    ],
                    warnings=[],
                    error=None,
                    additional_data=None,
                ),
                False,
                (None, None),
                textwrap.dedent(
                    """\
                   No affected source packages are installed.

                   {check} USN-### does not affect your system.
                   """.format(
                        check=messages.OKGREEN_CHECK  # noqa: E126
                    )  # noqa: E126
                ),
                FixStatus.SYSTEM_NOT_AFFECTED,
                [],
            ),
            (  # version is >= released affected package
                FixPlanResult(
                    title="USN-###",
                    description="test",
                    expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,
                    affected_packages=["slsrc"],
                    plan=[
                        FixPlanAptUpgradeStep(
                            data=AptUpgradeData(
                                binary_packages=[],
                                source_packages=["slsrc"],
                                pocket=STANDARD_UPDATES_POCKET,
                            ),
                            order=1,
                        )
                    ],
                    warnings=[],
                    error=None,
                    additional_data=None,
                ),
                False,
                (None, None),
                textwrap.dedent(
                    """\
                   1 affected source package is installed: slsrc
                   (1/1) slsrc:
                   A fix is available in Ubuntu standard updates.
                   The update is already installed.

                   {check} USN-### is resolved.
                   """.format(
                        check=messages.OKGREEN_CHECK  # noqa: E126
                    )  # noqa: E126
                ),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
            (  # installing package fix
                FixPlanResult(
                    title="USN-###",
                    description="test",
                    expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,
                    affected_packages=["slsrc"],
                    plan=[
                        FixPlanAptUpgradeStep(
                            data=AptUpgradeData(
                                binary_packages=["sl"],
                                source_packages=["slsrc"],
                                pocket=STANDARD_UPDATES_POCKET,
                            ),
                            order=1,
                        )
                    ],
                    warnings=[],
                    error=None,
                    additional_data=None,
                ),
                False,
                (None, None),
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
                + "{check} USN-### is resolved.\n".format(
                    check=messages.OKGREEN_CHECK
                ),
                FixStatus.SYSTEM_NON_VULNERABLE,
                [],
            ),
            (  # installing package fix that comes from esm-infra
                FixPlanResult(
                    title="USN-###",
                    description="test",
                    expected_status=FixStatus.SYSTEM_NON_VULNERABLE.value.msg,
                    affected_packages=["slsrc"],
                    plan=[
                        FixPlanAttachStep(
                            data=AttachData(
                                reason="test",
                                required_service=ESM_INFRA_POCKET,
                                source_packages=["slsrc"],
                            ),
                            order=1,
                        ),
                        FixPlanEnableStep(
                            data=EnableData(
                                service=ESM_INFRA_POCKET,
                                source_packages=["slsrc"],
                            ),
                            order=2,
                        ),
                        FixPlanAptUpgradeStep(
                            data=AptUpgradeData(
                                binary_packages=["sl"],
                                source_packages=["slsrc"],
                                pocket=STANDARD_UPDATES_POCKET,
                            ),
                            order=3,
                        ),
                    ],
                    warnings=[],
                    error=None,
                    additional_data=None,
                ),
                False,
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
                        messages.SECURITY_USE_PRO_TMPL.format(
                            title="Azure",
                            cloud_specific_url="https://ubuntu.com/azure/pro",
                        ),
                        messages.SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION,
                    ]
                ),
            ),
            FixStatus.SYSTEM_STILL_VULNERABLE,
            [],
        ),
    )
    @mock.patch("uaclient.cli.fix.get_cloud_type")
    @mock.patch("uaclient.security.util.prompt_choices", return_value="c")
    @mock.patch("uaclient.apt.run_apt_update_command")
    @mock.patch("uaclient.apt.run_apt_command")
    def test_execute_fix_plan(
        self,
        _m_apt_run_cmd,
        _m_apt_run_update,
        _m_prompt,
        m_get_cloud_type,
        fix_plan,
        dry_run,
        cloud_type,
        expected_output,
        expected_fix_status,
        expected_unfixed_pkgs,
        capsys,
        FakeConfig,
    ):
        m_get_cloud_type.return_value = cloud_type
        assert (
            expected_fix_status,
            expected_unfixed_pkgs,
        ) == execute_fix_plan(fix_plan, dry_run, FakeConfig())
        out, err = capsys.readouterr()
        if out != expected_output:
            print("[" + expected_output + "]")
            print("[" + out + "]")
        assert expected_output == out
