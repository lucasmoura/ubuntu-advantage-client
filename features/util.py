import os
import subprocess
import sys
import textwrap
import time
import yaml
from typing import Any, List

from behave.runner import Context

LXC_PROPERTY_MAP = {
    "image": {"series": "properties.release", "machine_type": "Type"},
    "container": {"series": "image.release", "machine_type": "image.type"},
}
SOURCE_PR_TGZ = "/tmp/pr_source.tar.gz"
VM_PROFILE_TMPL = "behave-{}"

# For Xenial and Bionic vendor-data required to setup lxd-agent
# Additionally xenial needs to launch images:ubuntu/16.04/cloud
# because it contains the HWE kernel which has vhost-vsock support
LXC_SETUP_VENDORDATA = textwrap.dedent(
    """\
    config:
      user.vendor-data: |
        #cloud-config
        {custom_cfg}
        write_files:
        - path: /var/lib/cloud/scripts/per-once/setup-lxc.sh
          encoding: b64
          permissions: '0755'
          owner: root:root
          content: |
              IyEvYmluL3NoCmlmICEgZ3JlcCBseGRfY29uZmlnIC9wcm9jL21vdW50czsgdGhlbgogICAgbWtk
              aXIgLXAgL3J1bi9seGRhZ2VudAogICAgbW91bnQgLXQgOXAgY29uZmlnIC9ydW4vbHhkYWdlbnQK
              ICAgIFZJUlQ9JChzeXN0ZW1kLWRldGVjdC12aXJ0KQogICAgY2FzZSAkVklSVCBpbgogICAgICAg
              IHFlbXV8a3ZtKQogICAgICAgICAgICAoY2QgL3J1bi9seGRhZ2VudC8gJiYgLi9pbnN0YWxsLnNo
              KQogICAgICAgICAgICB1bW91bnQgL3J1bi9seGRhZ2VudAogICAgICAgICAgICBzeXN0ZW1jdGwg
              c3RhcnQgbHhkLWFnZW50LTlwIGx4ZC1hZ2VudAogICAgICAgICAgICA7OwogICAgICAgICopCiAg
              ICBlc2FjCmZpCg==
   """
)


def launch_lxd_container(
    context: Context,
    image_name: str,
    container_name: str,
    series: str,
    is_vm: bool,
) -> None:
    """Launch a container from an image and wait for it to boot

    This will also register a cleanup with behave so the container will be
    removed before test execution completes.

    :param context:
        A `behave.runner.Context`; used only for registering cleanups.
    :param image_name:
        The name of the lxd image to launch as base image for the container
    :param container_name:
        The name to be used for the launched container.
    :param series: A string representing the series of the vm to create
    :param is_vm:
        Boolean as to whether or not to launch KVM type container
    :param user_data:
        Optional str of userdata to pass to the launched image
    """
    command = ["lxc", "launch", image_name, container_name]
    if is_vm:
        lxc_create_vm_profile(series)
        command.extend(["--profile", VM_PROFILE_TMPL.format(series), "--vm"])
    subprocess.run(command)

    if is_vm:
        """ When we publish vm images we end up loosing the image information.
        Since we need at least the release information to reuse the vm instance
        in other tests, we are adding this information back here."""
        subprocess.run(["lxc", "stop", container_name])
        subprocess.run(
            ["lxc", "config", "set", container_name, "image.release", series]
        )
        subprocess.run(["lxc", "start", container_name])

    def cleanup_container() -> None:
        if not context.config.destroy_instances:
            print("Leaving lxd container running: {}".format(container_name))
        else:
            subprocess.run(["lxc", "delete", "-f", container_name])

    context.add_cleanup(cleanup_container)

    wait_for_boot(container_name, series=series, is_vm=is_vm)


def lxc_exec(
    container_name: str,
    cmd: List[str],
    capture_output: bool = False,
    text: bool = False,
    **kwargs: Any
) -> subprocess.CompletedProcess:
    """Run `lxc exec` in a container.

    :param container_name:
        The name of the container to run `lxc exec` against.
    :param cmd:
        A list containing the command to be run and its parameters; this will
        be appended to a list that is passed to `subprocess.run`.
    :param capture_output:
        If capture_output is true, stdout and stderr will be captured.  (On
        pre-3.7 Pythons, this will behave as capture_output does for 3.7+.  On
        3.7+, this is just passed through.)
    :param text:
        If text (also known as universal_newlines) is true, the file objects
        stdin, stdout and stderr will be opened in text mode. (On pre-3.7
        Pythons, this will behave as universal_newlines does).
    :param kwargs:
        These are passed directly to `subprocess.run`.

    :return:
        The `subprocess.CompletedProcess` returned by `subprocess.run`.
    """
    if sys.version_info >= (3, 7):
        # We have native capture_output support
        kwargs["capture_output"] = capture_output
        kwargs["text"] = text
    elif capture_output:
        if (
            kwargs.get("stdout") is not None
            or kwargs.get("stderr") is not None
        ):
            raise ValueError(
                "stdout and stderr arguments may not be used "
                "with capture_output."
            )
        # stdout and stderr will be opened in text mode (by default they are
        # opened in binary mode
        kwargs["universal_newlines"] = text
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    return subprocess.run(
        ["lxc", "exec", "--user", "1000", container_name, "--"] + cmd, **kwargs
    )


def lxc_create_vm_profile(series: str):
    """Create a vm profile to enable launching kvm instances"""

    content_tmpl = textwrap.dedent(
        """\
        {vendordata}
        description: Default LXD profile for {series} VMs
        devices:
          config:
            source: cloud-init:config
            type: disk
          eth0:
            name: eth0
            network: lxdbr0
            type: nic
          root:
            path: /
            pool: default
            type: disk
        name: vm
    """
    )
    if series == "xenial":
        # FIXME: Xenial images from images:ubuntu/16.04/cloud have HWE kernel
        # but no openssh-server (which fips testing would expect)
        # Work with CPC to get vhost-vsock support if possible to use
        # ubuntu-daily:xenial images
        content = content_tmpl.format(
            vendordata=LXC_SETUP_VENDORDATA.format(
                custom_cfg="packages: [openssh-server]"
            ),
            series=series,
        )
    elif series == "bionic":
        content = content_tmpl.format(
            vendordata=LXC_SETUP_VENDORDATA.format(custom_cfg=""),
            series=series,
        )
    elif series == "focal":
        content = content_tmpl.format(vendordata="config: {}", series=series)
    else:
        raise RuntimeError(
            "===No lxc mv support for series {}====".format(series)
        )
    output = subprocess.check_output(["lxc", "profile", "list"])
    profile_name = VM_PROFILE_TMPL.format(series)
    if " {} ".format(profile_name) not in output.decode("utf-8"):
        subprocess.run(["lxc", "profile", "create", profile_name])
        proc = subprocess.Popen(
            ["lxc", "profile", "edit", profile_name], stdin=subprocess.PIPE
        )
        proc.communicate(content.encode())


def wait_for_boot(
    container_name: str, series: str, is_vm: bool = False
) -> None:
    """Wait for a test container to boot.

    :param container_name:
        The name of the container to wait for.
    :param series:
        The Ubuntu series we are waiting for.
    :param is_vm:
        Boolean as to whether or not to launch KVM type container
    """
    if is_vm:
        retries = [30, 45, 60, 75, 90, 105]
    else:
        retries = [5, 10, 15, 20, 20, 30]
    if series != "trusty":
        retcode = 1
        for sleep_time in retries:
            proc = lxc_exec(
                container_name,
                ["cloud-init", "status", "--wait", "--long"],
                capture_output=True,
                text=True,
            )
            retcode = proc.returncode
            if retcode == 0:
                break
            print(
                "Retrying on unexpected cloud-init status stderr: ",
                proc.stderr.strip(),
            )
            time.sleep(sleep_time)
        if retcode != 0:
            raise Exception("System did not boot in {}s".format(sum(retries)))
        return
    for sleep_time in retries:
        process = lxc_exec(
            container_name, ["runlevel"], capture_output=True, text=True
        )
        try:
            _, runlevel = process.stdout.strip().split(" ", 2)
        except ValueError:
            print("Unexpected runlevel output: ", process.stdout.strip())
            runlevel = None
        if runlevel in ("2", "5"):
            break
        time.sleep(sleep_time)
    else:
        raise Exception("System did not boot in {}s".format(sum(retries)))


def lxc_get_property(name: str, property_name: str, image: bool = False):
    """Check series name of either an image or a container.

    :param name:
        The name of the container or the image to check its series.
    :param property_name:
        The name of the property to return.
    :param image:
        If image==True will check image properties
        If image==False it will check container configuration to get
        properties.

    :return:
        The value of the container or image property.
       `None` if it could not detect it (
           some images don't have this field in properties).
    """
    if not image:
        property_name = LXC_PROPERTY_MAP["container"][property_name]
        output = subprocess.check_output(
            ["lxc", "config", "get", name, property_name],
            universal_newlines=True,
        )
        return output.rstrip()
    else:
        property_keys = LXC_PROPERTY_MAP["image"][property_name].split(".")
        output = subprocess.check_output(
            ["lxc", "image", "show", name], universal_newlines=True
        )
        image_config = yaml.safe_load(output)
        print(" `lxc image show` output: ", image_config)
        value = image_config
        for key_name in property_keys:
            value = image_config.get(value, {})
        if not value:
            print(
                "Could not detect image property {name}."
                " Add it via `lxc image edit`".format(
                    name=".".join(property_keys)
                )
            )
            return None
        return value


def lxc_build_deb(container_name: str, output_deb_file: str) -> None:
    """
    Push source PR code .tar.gz to the container.
    Run tools/build-from-source.sh which will create the .deb
    Pull .deb from this container to travis-ci instance

    :param container_name: the name of the container to:
         - push the PR source code;
         - pull the built .deb package.
    :param output_deb_file: the new output .deb from source code
    """

    print("\n\n\n LXC file push {}".format(SOURCE_PR_TGZ))
    if not os.environ.get("TRAVIS"):
        print(
            "\n\n\n Assuming non-travis build. Creating: {}".format(
                SOURCE_PR_TGZ
            )
        )
        os.chdir("..")
        subprocess.run(
            ["tar", "-zcvf", SOURCE_PR_TGZ, "ubuntu-advantage-client"]
        )
        os.chdir("ubuntu-advantage-client")
    subprocess.run(
        ["lxc", "file", "push", SOURCE_PR_TGZ, container_name + "/tmp/"]
    )
    script = "build-from-source.sh"
    with open(script, "w") as stream:
        stream.write(
            textwrap.dedent(
                """\
            #!/bin/bash
            set -o xtrace
            apt-get update
            apt-get install make
            cd /tmp
            tar -zxvf *gz
            cd ubuntu-advantage-client
            make deps
            dpkg-buildpackage -us -uc
            cp /tmp/ubuntu-advantage-tools*.deb /tmp/ubuntu-advantage-tools.deb

            ls -lh /tmp
         """
            )
        )
    os.chmod(script, 0o755)
    subprocess.run(["ls", "-lh", "/tmp"])
    print("\n\n\n LXC file push script build-from-source")
    subprocess.run(["lxc", "file", "push", script, container_name + "/tmp/"])
    print("\n\n\n Run build-from-source.sh")
    lxc_exec(container_name, ["sudo", "/tmp/" + script])
    print("\n\nPull {} from the instance to travis VM".format(output_deb_file))
    subprocess.run(
        [
            "lxc",
            "file",
            "pull",
            container_name + "/tmp/ubuntu-advantage-tools.deb",
            output_deb_file,
        ]
    )
