import contextlib
import io
import mock

import pytest

from uaclient.cli import _perform_enable, action_enable
from uaclient import exceptions
from uaclient import status


@mock.patch("uaclient.cli.os.getuid")
class TestActionEnable:
    def test_non_root_users_are_rejected(self, getuid, FakeConfig):
        """Check that a UID != 0 will receive a message and exit non-zero"""
        getuid.return_value = 1

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.NonRootUserError):
            action_enable(mock.MagicMock(), cfg)

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_ENABLE_FAILURE_UNATTACHED_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_unattached_error_message(
        self, m_getuid, uid, expected_error_template, FakeConfig
    ):
        """Check that root user gets unattached message."""

        m_getuid.return_value = uid
        cfg = FakeConfig()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.names = ["esm-infra"]
            action_enable(args, cfg)
        assert (
            expected_error_template.format(name="esm-infra") == err.value.msg
        )

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_invalid_service_error_message(
        self, m_getuid, uid, expected_error_template, FakeConfig
    ):
        """Check invalid service name results in custom error message."""

        m_getuid.return_value = uid
        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.names = ["bogus"]
            action_enable(args, cfg)
        assert (
            expected_error_template.format(operation="enable", name="bogus")
            == err.value.msg
        )

    @pytest.mark.parametrize("beta_flag, beta_count", ((False, 1), (True, 0)))
    @pytest.mark.parametrize("assume_yes", (True, False))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.contract.request_updated_contract")
    @mock.patch("uaclient.cli.entitlements")
    def test_assume_yes_passed_to_service_init(
        self,
        m_entitlements,
        m_request_updated_contract,
        _m_get_available_resources,
        m_getuid,
        assume_yes,
        beta_flag,
        beta_count,
        FakeConfig,
    ):
        """assume-yes parameter is passed to entitlement instantiation."""
        m_getuid.return_value = 0

        m_entitlement_cls = mock.MagicMock()
        m_ent_is_beta = mock.PropertyMock(return_value=False)
        type(m_entitlement_cls).is_beta = m_ent_is_beta
        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "testitlement": m_entitlement_cls
        }
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.enable.return_value = True

        cfg = FakeConfig.for_attached_machine()
        args = mock.MagicMock()
        args.names = ["testitlement"]
        args.assume_yes = assume_yes
        args.beta = beta_flag
        action_enable(args, cfg)
        assert [
            mock.call(cfg, assume_yes=assume_yes)
        ] == m_entitlement_cls.call_args_list
        assert beta_count == m_ent_is_beta.call_count

    @pytest.mark.parametrize("beta_flag, beta_count", ((False, 1), (True, 0)))
    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.cli.entitlements")
    def test_entitlements_not_found_disabled_and_enabled(
        self,
        m_entitlements,
        _m_get_available_resources,
        m_getuid,
        silent_if_inapplicable,
        beta_flag,
        beta_count,
        FakeConfig,
    ):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL

        m_ent1_cls = mock.Mock()
        m_ent1_obj = m_ent1_cls.return_value
        m_ent1_obj.enable.return_value = False

        m_ent2_cls = mock.Mock()
        m_ent2_is_beta = mock.PropertyMock(return_value=False)
        type(m_ent2_cls).is_beta = m_ent2_is_beta
        m_ent2_obj = m_ent2_cls.return_value
        m_ent2_obj.enable.return_value = False

        m_ent3_cls = mock.Mock()
        m_ent3_is_beta = mock.PropertyMock(return_value=False)
        type(m_ent3_cls).is_beta = m_ent3_is_beta
        m_ent3_obj = m_ent3_cls.return_value
        m_ent3_obj.enable.return_value = True

        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "ent2": m_ent2_cls,
            "ent3": m_ent3_cls,
        }

        cfg = FakeConfig.for_attached_machine()
        assume_yes = False
        args_mock = mock.Mock()
        args_mock.names = ["ent1", "ent2", "ent3"]
        args_mock.assume_yes = assume_yes
        args_mock.beta = beta_flag

        expected_msg = "One moment, checking your subscription first\n"

        with pytest.raises(exceptions.UserFacingError) as err:
            fake_stdout = io.StringIO()
            with contextlib.redirect_stdout(fake_stdout):
                action_enable(args_mock, cfg)

        assert (
            expected_error_tmpl.format(operation="enable", name="ent1")
            == err.value.msg
        )
        assert expected_msg == fake_stdout.getvalue()

        for m_ent_cls in [m_ent2_cls, m_ent3_cls]:
            assert [
                mock.call(cfg, assume_yes=assume_yes)
            ] == m_ent_cls.call_args_list

        expected_enable_call = mock.call(silent_if_inapplicable=False)
        for m_ent in [m_ent2_obj, m_ent3_obj]:
            assert [expected_enable_call] == m_ent.enable.call_args_list

        assert 0 == m_ent1_obj.call_count
        assert beta_count == m_ent2_is_beta.call_count
        assert beta_count == m_ent3_is_beta.call_count

    @pytest.mark.parametrize("beta_flag, beta_count", ((False, 1), (True, 0)))
    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.cli.entitlements")
    def test_entitlements_not_found_and_beta(
        self,
        m_entitlements,
        _m_get_available_resources,
        m_getuid,
        silent_if_inapplicable,
        beta_flag,
        beta_count,
        FakeConfig,
    ):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL

        m_ent1_cls = mock.Mock()
        m_ent1_obj = m_ent1_cls.return_value
        m_ent1_obj.enable.return_value = False

        m_ent2_cls = mock.Mock()
        m_ent2_is_beta = mock.PropertyMock(return_value=True)
        type(m_ent2_cls).is_beta = m_ent2_is_beta
        m_ent2_obj = m_ent2_cls.return_value
        m_ent2_obj.enable.return_value = False

        m_ent3_cls = mock.Mock()
        m_ent3_is_beta = mock.PropertyMock(return_value=False)
        type(m_ent3_cls).is_beta = m_ent3_is_beta
        m_ent3_obj = m_ent3_cls.return_value
        m_ent3_obj.enable.return_value = True

        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "ent2": m_ent2_cls,
            "ent3": m_ent3_cls,
        }

        cfg = FakeConfig.for_attached_machine()
        assume_yes = False
        args_mock = mock.Mock()
        args_mock.names = ["ent1", "ent2", "ent3"]
        args_mock.assume_yes = assume_yes
        args_mock.beta = beta_flag

        expected_msg = "One moment, checking your subscription first\n"

        with pytest.raises(exceptions.UserFacingError) as err:
            fake_stdout = io.StringIO()
            with contextlib.redirect_stdout(fake_stdout):
                action_enable(args_mock, cfg)

        not_found_name = "ent1"
        mock_ent_list = [m_ent3_cls]
        mock_obj_list = [m_ent3_obj]

        if not beta_flag:
            not_found_name += ", ent2"
        else:
            mock_ent_list.append(m_ent2_cls)
            mock_obj_list.append(m_ent3_obj)

        assert (
            expected_error_tmpl.format(operation="enable", name=not_found_name)
            == err.value.msg
        )
        assert expected_msg == fake_stdout.getvalue()

        for m_ent_cls in mock_ent_list:
            assert [
                mock.call(cfg, assume_yes=assume_yes)
            ] == m_ent_cls.call_args_list

        expected_enable_call = mock.call(silent_if_inapplicable=False)
        for m_ent in mock_obj_list:
            assert [expected_enable_call] == m_ent.enable.call_args_list

        assert 0 == m_ent1_obj.call_count
        assert beta_count == m_ent2_is_beta.call_count
        assert beta_count == m_ent3_is_beta.call_count

    @pytest.mark.parametrize("names", [["bogus"], ["bogus1", "bogus2"]])
    def test_invalid_service_names(self, m_getuid, names, FakeConfig):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL
        expected_msg = "One moment, checking your subscription first\n"

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            fake_stdout = io.StringIO()
            with contextlib.redirect_stdout(fake_stdout):
                args = mock.MagicMock()
                args.names = names
                action_enable(args, cfg)

        assert expected_msg == fake_stdout.getvalue()
        assert (
            expected_error_tmpl.format(
                operation="enable", name=", ".join(sorted(names))
            )
            == err.value.msg
        )


class TestPerformEnable:
    @mock.patch("uaclient.cli.entitlements")
    def test_missing_entitlement_raises_keyerror(self, m_entitlements):
        """We raise a KeyError on missing entitlements

        (This isn't a problem because any callers of _perform_enable should
        already have rejected invalid names.)
        """
        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {}

        with pytest.raises(KeyError):
            _perform_enable("entitlement", mock.Mock())

    @pytest.mark.parametrize(
        "allow_beta, beta_call_count", ((True, 0), (False, 1))
    )
    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.cli.entitlements")
    def test_entitlement_instantiated_and_enabled(
        self,
        m_entitlements,
        _m_get_available_resources,
        silent_if_inapplicable,
        allow_beta,
        beta_call_count,
    ):
        m_entitlement_cls = mock.Mock()
        m_cfg = mock.Mock()
        m_user_cfg = mock.PropertyMock(return_value={})
        type(m_cfg).cfg = m_user_cfg
        m_is_beta = mock.PropertyMock(return_value=allow_beta)
        type(m_entitlement_cls).is_beta = m_is_beta

        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "testitlement": m_entitlement_cls
        }

        kwargs = {"allow_beta": allow_beta}
        if silent_if_inapplicable is not None:
            kwargs["silent_if_inapplicable"] = silent_if_inapplicable
        ret = _perform_enable("testitlement", m_cfg, **kwargs)

        assert [
            mock.call(m_cfg, assume_yes=False)
        ] == m_entitlement_cls.call_args_list

        m_entitlement = m_entitlement_cls.return_value
        if silent_if_inapplicable:
            expected_enable_call = mock.call(silent_if_inapplicable=True)
        else:
            expected_enable_call = mock.call(silent_if_inapplicable=False)
        assert [expected_enable_call] == m_entitlement.enable.call_args_list
        assert ret == m_entitlement.enable.return_value

        assert 1 == m_cfg.status.call_count
        assert 1 == m_user_cfg.call_count
        assert beta_call_count == m_is_beta.call_count

    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.cli.entitlements")
    def test_beta_entitlement_not_enabled(
        self, m_entitlements, silent_if_inapplicable
    ):
        m_entitlement_cls = mock.Mock()
        m_cfg = mock.Mock()
        m_user_cfg = mock.PropertyMock(return_value={})
        type(m_cfg).cfg = m_user_cfg
        m_is_beta = mock.PropertyMock(return_value=True)
        type(m_entitlement_cls).is_beta = m_is_beta

        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "testitlement": m_entitlement_cls
        }

        kwargs = {"allow_beta": False}
        if silent_if_inapplicable is not None:
            kwargs["silent_if_inapplicable"] = silent_if_inapplicable

        with pytest.raises(exceptions.BetaServiceError):
            _perform_enable("testitlement", m_cfg, **kwargs)

        assert 1 == m_is_beta.call_count
        assert 1 == m_user_cfg.call_count

    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.cli.entitlements")
    def test_beta_entitlement_instantiated_and_enabled_with_config_override(
        self,
        m_entitlements,
        _m_get_available_resources,
        silent_if_inapplicable,
    ):
        ent_name = "testitlement"
        cfg_dict = {"features": {"allow_beta": True}}
        m_entitlement_cls = mock.Mock()
        m_cfg = mock.Mock()
        m_cfg_dict = mock.PropertyMock(return_value=cfg_dict)
        type(m_cfg).cfg = m_cfg_dict

        m_is_beta = mock.PropertyMock(return_value=True)
        type(m_entitlement_cls).is_beta = m_is_beta

        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            ent_name: m_entitlement_cls
        }

        kwargs = {"allow_beta": False}
        if silent_if_inapplicable is not None:
            kwargs["silent_if_inapplicable"] = silent_if_inapplicable
        ret = _perform_enable(ent_name, m_cfg, **kwargs)

        assert [
            mock.call(m_cfg, assume_yes=False)
        ] == m_entitlement_cls.call_args_list

        m_entitlement = m_entitlement_cls.return_value
        if silent_if_inapplicable:
            expected_enable_call = mock.call(silent_if_inapplicable=True)
        else:
            expected_enable_call = mock.call(silent_if_inapplicable=False)
        assert [expected_enable_call] == m_entitlement.enable.call_args_list
        assert ret == m_entitlement.enable.return_value

        assert 1 == m_cfg.status.call_count
        assert 0 == m_is_beta.call_count
        assert 1 == m_cfg_dict.call_count
