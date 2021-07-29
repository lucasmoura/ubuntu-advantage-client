import json
import logging
import os

import datetime

from uaclient.config import UAConfig
from uaclient import util
from uaclient.jobs.update_messaging import update_apt_and_motd_messages

LOG = logging.getLogger(__name__)

# We are currently storing the time frequency for each job at this dict,
# but we should move it later into uaclient.conf
uaclient_jobs = {
    "update_messaging": {
        "job_func": update_apt_and_motd_messages,
        "time_frequency": 4,
    },
    "update_status": {"job_func": lambda: None, "time_frequency": 4},
}


def get_current_time():
    return datetime.datetime.now()


def run_job(job_name, job_func, time_frequency, jobs_status):
    if job_name in jobs_status:
        last_run = jobs_status[job_name]["last_run"]
        hours_to_add = datetime.timedelta(hours=time_frequency)
        current_time = get_current_time()

        if current_time < (last_run + hours_to_add):
            return {}

    try:
        job_func()
    except Exception as e:
        LOG.warning("Error executing job: %s", job_name)
        LOG.warning("The following exception was raised:\n%s", str(e))
        return {}

    return {job_name: {"last_run": current_time}}


def main():
    cfg = UAConfig()
    jobs_status_path = cfg.data_path("jobs-status")

    jobs_status = {}
    if os.path.exists(jobs_status_path):
        jobs_status = json.loads(
            util.load_file(jobs_status_path), cls=util.DatetimeAwareJSONDecoder
        )

    for job_name, job_info in uaclient_jobs.items():
        job_func = job_info["job_func"]
        time_frequency = job_info["time_frequency"]

        jobs_status.update(
            run_job(job_name, job_func, time_frequency, jobs_status)
        )

    content = json.dumps(jobs_status, cls=util.DatetimeAwareJSONEncoder)
    util.write_file(jobs_status_path, content)
