import mock
import pytest

from uaclient.util import parse_rfc3339_date
from lib.timer import run_job


class TestRunJob:
    @pytest.mark.parametrize(
        "last_run,time_frequency,should_run",
        (
            ("2021-07-29T12:00:00Z", 4, False),
            ("2021-07-29T11:00:00Z", 4, True),
            ("2021-07-29T12:00:00Z", 1, True),
        ),
    )
    @mock.patch("lib.timer.get_current_time")
    def test_run_job(
        self, m_current_time, last_run, time_frequency, should_run
    ):
        jobs_status = {"test_job": {"last_run": parse_rfc3339_date(last_run)}}

        job_func = mock.Mock()
        current_time = parse_rfc3339_date("2021-07-29T15:02:00Z")
        m_current_time.return_value = current_time

        job_ret = run_job(
            job_name="test_job",
            job_func=job_func,
            time_frequency=time_frequency,
            jobs_status=jobs_status,
        )

        if should_run:
            assert job_func.call_count == 1
            assert job_ret == {"test_job": {"last_run": current_time}}
        else:
            assert job_func.call_count == 0
            assert job_ret == {}
